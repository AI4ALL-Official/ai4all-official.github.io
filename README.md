# Fake or Nah

The purpose of our project was to create an accurate and efficient fake news detector using Natural Language Processing (NLP). After testing different identfiers that differentiate fake news from true news, we chose to test several different models to train with our data. Among the models that we tested were Logistic Regression, ⁠XGBoost Classifier, Gradient Boosting Classifier, and ⁠Random Forest Classifier. We used a dataset called fake-and-real-news-dataset found on Kaggle for this project. We employed advanced Python techniques and data analysis methodologies, all within AI4ALL's cutting-edge AI4ALL Ignite accelerator.


## Problem Statement <!--- do not change this line -->

Fake news has been a great problem, whether its purpose is to spread propaganda, misinformation or for another malicious intent. Our goal was to create a project that allows people to check the verity of their articles before believing their information.

## Key Results <!--- do not change this line -->

1. Used over 44,000 articles to train a linear regression model with 99% accuracy
2. Identified 10 identifiers that are supported by the data we are using. 


## Methodologies <!--- do not change this line -->

To investigate how linguistic cues can help distinguish real news from fabricated stories, we trained a series of supervised machine learning models using the Fake-and-Real-News Dataset from Kaggle. After combining and labeling both CSV files, we performed data cleaning, removed duplicates, and conducted exploratory analysis to identify topical or source-related biases. We then preprocessed the text using tokenization, minimal normalization, and feature extraction, incorporating both transformer-ready text inputs and engineered linguistic features such as n-gram frequencies, sentiment, readability scores, and part-of-speech distributions.

Our experiments compared classical models (including logistic regression, SVM, and XGBoost), deep learning approaches, and transformer-based architectures fine-tuned for binary classification. All models were trained using a stratified train-validation-test split, with an additional source-holdout set to check for overfitting and leakage. Performance was evaluated using accuracy, precision, recall, F1 score, and error analysis to assess which linguistic signals the models relied on and how well they generalized to unseen data.


## Data Sources <!--- do not change this line -->

[Kaggle Datasets:](https://www.kaggle.com/datasets/clmentbisaillon/fake-and-real-news-dataset)
* fake.csv
* true.csv

## Technologies Used <!--- do not change this line -->
##### Languages & Tools
- *Python*
- *Jupyter Notebooks*
- *pandas*
- *Gemini 3.0*

##### Libraries
- *pandas*
- *numpy*
- *matplotlib*
- *seaborn*
- *nltk*
- *pathlib*
- *better_profanity*
- *scipy*


## Authors <!--- do not change this line -->
*This project was completed in collaboration with:*
- *Nina Elmoyan ([nelmoya509@student.glendale.edu](mailto:nelmoya509@student.glendale.edu))*
- *Rhode Sanchez ([rsanc266@fiu.edu](mailto:rsanc266@fiu.edu))*
- *Wynne Conger ([wc2918@princeton.edu](mailto:wc2918@princeton.edu))*
- *Ramneek Kaur([rnolas61@asu.edu](mailto:rnolas61@asu.edu))*
