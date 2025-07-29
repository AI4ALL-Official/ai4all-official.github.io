import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

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

clean_csv('thursday_plus.csv')


#Tuesday
dfTuesday = pd.read_csv("tuesday.csv", skipinitialspace=True)

columns_to_delete = ['Src IP dec', 'Dst IP dec', 'Src Port', 'Dst Port', 'Timestamp', 'ICMP Code', 'ICMP Type', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd RST Flags', 'Bwd RST Flags', 'Fwd PSH Flags', 'Bwd PSH Flags', 'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Fwd Act Data Pkts', 'Fwd Seg Size Min','Attempted Category']
#df_parts_to_remove = df[columns_to_delete]
#df.columns = df.columns.str.strip()
#print(df.columns)

dfTuesday = dfTuesday.drop(columns = columns_to_delete)

#0 = Bening and 1 = Attack, I want to figure out how to make it output multiple numbers for each attack
encoder = LabelEncoder()

dfTuesday['Label'] = encoder.fit_transform(dfTuesday['Label'])
