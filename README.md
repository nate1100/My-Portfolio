# My-Portfolio
# Project 1: PHISHCHECK: A BROWSER-BASED EXTENSION FOR PHISHING ATTACK DETECTION USING MACHINE LEARNING APPROACH <br />
## Project Overview
*Collected large dataset from multiple resources including Phishtank,OpenPhish and Kaggle.<br />
*Discovered the phishing anomaly using supervised algorithms such as Random Forest, SVM and XGBoost in terms of accuracy, precision, recall, f-measure and confusion matrix.<br />
*Identified the characteristics of phishing URLs.<br />
*Developed a browser-based extension that shall automatically categorize each URL as legitimate or phishing.

## Architectural Paradigm of the Study
This project used two important components further understand the cycle: the PhishCheck Chrome extension, which serves as the front-end, and Python, which serves as the study's back-end. Front-end components such as pop-up window and background scripts are some of the important parts of chrome extensions that were navigated first when users visit a website or enter a url in the pop-up address bar. <br />

![](images/1.png)

# Data Preparation
The study's data preparation is divided into two parts: data preprocessing and feature engineering.
## Data Preprocessing 
The researchers used Python programming which uses libraries such as numpy, pandas, matplotlib and seaborn for the data preprocessing. Initially, the researchers combined all of the data cleaning into a single piece of code. After reviewing the dataset, it was discovered that there were numerous errors, including additional white spaces, null values, unnecessary columns, and duplicates. To further clean the dataset, the researchers concluded that these noises must be removed at each stage. 


'import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

#Import data
data = pd.read_csv(r"C:\Users\user\OneDrive\Desktop\Thesis1_Phishing\cleaned_finaldataset.csv")
data.head()'


