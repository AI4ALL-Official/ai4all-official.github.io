import pandas as pd
import numpy as np

print("Running test script")
print("Script started")

def clean_csv(file_name):
    print(f"Cleaning {file_name}...")

    try:
        df = pd.read_csv(file_name)
    except Exception as e:
        print(f"Error loading file: {e}")
        return

    # Drop unneeded columns (keep 'Label' or 'Attempted Category' for categories)
    columns_to_drop = [
        'Src IP dec', 'Dst IP dec', 'Timestamp',
        'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
        'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
        # Drop Attempted Category only if you don't want it
        # 'Attempted Category'
    ]
    df.drop(columns=columns_to_drop, inplace=True, errors='ignore')

    # Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop columns with >50% missing data
    df.dropna(thresh=len(df)*0.5, axis=1, inplace=True)

    # Fill remaining NaNs with median
    df.fillna(df.median(numeric_only=True), inplace=True)

    # Drop duplicates
    df.drop_duplicates(inplace=True)

    # Map labels to categories
    # Keep 'BENIGN' as 'Benign', others keep original attack names for multi-class classification
    df['Label'] = df['Label'].apply(lambda x: 'Benign' if x == 'BENIGN' else x)

    # check unique attack categories present
    print("Unique Labels after mapping:", df['Label'].unique())

    # Save cleaned data
    output_file = file_name.replace('.csv', '_cleaned.csv')
    try:
        df.to_csv(output_file, index=False)
        print(f"Data cleaned and saved to '{output_file}'")
    except Exception as e:
        print(f"Error saving file: {e}")

clean_csv('monday_plus.csv')