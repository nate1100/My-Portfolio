# PROJECT 2: Sentiment Analysis of Twitter Data in Predicting the Philippines’ Winning Presidential Candidate <br />
## Project Overview
*Determine the attitudes and feelings of people in selecting candidates for the coming election through tweets. <br />
*Implement an algorithm to classify the tweets, whether they're positive or negative.<br />
*Present the graphical representation of sentiments on Twitter for predicting electoral outcomes.

## Data Collection
TWINT was used to extract tweets in the Twitter. TWINT allowed the researchers to bypass the constraints of the Twitter API, it also has the advantage of being easy to use, 
```
import twint
def scrapeTweet(searchTerms, limit, startDate, endDate, outputFile):
    for i in range(len(searchTerms)):
        c = twint.Config()
        c.Search = searchTerms[i] 
        c.Limit = limit  #set limit
        c.Lang = "en"
        c.Since = startDate
        c.Until = endDate
        c.Store_csv = True
        c.Output = outputFile

        twint.run.Search(c)

searchTerms = ['sample']   #can include other filters -person -politician for annotated tweet 
outputFile = 'sample.csv' 
limit = 2000 #set limit per search term.
startDate = '2022-03-22 00:00:00' #set start date
endDate = '2022-03-25 23:59:59' #set end date

#Scraping tweet older than 2 weeks result to fewer scraped tweets.
scrapeTweet(searchTerms, limit, startDate, endDate, outputFile)
```

| Presidential Candidate    | Tweets |
| -------- | ------- |
| Leni G. Robredo  | 36,941    |
| Ferdinand R. Marcos Jr. | 13,063     |
| Francisco M. Domagoso| 4,595    |

## DATA PREPROCESSING

### Fist Stage of Cleaning
*Noise characters such as punctuations, symbols, extra white spaces, new line characters conversion to space, single characters such as ‘t’ and ‘d’ and numbers resulted from any form of text cleaning has been removed. Moreover, all the uppercase of the dataset have been converted to lowercase and empty tweets resulted from the data cleaning have been removed to further clean the dataset.*

```
library(tidyverse)    

#First stage of cleaning

tweetCleaner <- function(tweet) {
    cleanTweet <- tweet
    
    # Remove URLs
    cleanTweet <- str_remove_all(cleanTweet, " ?(f|ht)(tp)(s?)(://)(.*)[.|/](.*)")
    
    # Remove mentions
    cleanTweet <- str_remove_all(cleanTweet, "@[[:alnum:]_]{4,}")
    
    # Remove Hashtags
    cleanTweet <- str_remove_all(cleanTweet, "#[[:alnum:]_]+")
    
    # Remove punctuation
    cleanTweet <- str_remove_all(cleanTweet, "[[:punct:]]")
    
    # Remove Retweets RT:
    cleanTweet <- str_remove_all(cleanTweet, "^RT:? ")
    
    # Replace newline characters with a space
    cleanTweet <- str_replace_all(cleanTweet, "\\\n", " ")
    
    # Convert to Lowercase
    cleanTweet <- str_to_lower(cleanTweet)

    return(cleanTweet)
}


#Only preserve 'tweet' attribute
createDataFrame <- function(cleanTweet) {
  newDataFrame <- data.frame(tweet = c(cleanTweet))
  return(newDataFrame)
}

#Edit what file is to be cleaned
inputFile <- "sample.csv"
outputFile <- "sameple_o.csv"

readFile <- read.csv(inputFile)
cleanTweet <- tweetCleaner(readFile$tweet)
newDataFrame <- createDataFrame(cleanTweet)
write.csv(newDataFrame, outputFile)
```
### Second Stage of Cleaning
*The usage of emoji in a tweet is common for twitter users, it may be used in future studies in sentimental analysis but since this study is focused on texts, any emoji has been removed. Emojis are read as Unicode characters so a string pattern ‘<U+ >’ have been used to eliminate such emojis. Conversion of non-ascii characters to its alphabet counterpart. Example of this is ‘â’ to ‘a’. It is uncommon for users to look at these type of characters to be stylish but some do, so it is considered to be converted for a cleaner data.*

```
library(tidyverse)    
library(stringi)

tweetCleaner <- function(tweet) {
    cleanTweet <- tweet
    
    #Remove unicode characters (emojis <U+*> pattern )
    cleanTweet <- gsub("[<].*[>]", "", cleanTweet)
    
    #Non-ascii text conversion to preserve text
    cleanTweet <- stri_trans_general(cleanTweet, "latin-ascii")
    
    #Remove any alphanumeric symbols left
    cleanTweet <- str_replace_all(cleanTweet, "[^[:alnum:]]", " ")
    
    #Remove leading and trailing white space
    cleanTweet <- gsub("^\\s+|\\s+$", "", cleanTweet)

    #Remove extra white space
    cleanTweet <- gsub("\\s+", " ", cleanTweet)
    
    return(cleanTweet)
}

#Only preserve 'tweet' attribute
createDataFrame <- function(cleanTweet) {
  newDataFrame <- data.frame(tweet = c(cleanTweet))
  return(newDataFrame)
}

#Enter file name for input and output
inputFile <- "sample.csv"
outputFile <- "sample.o.csv"

readFile <- read.csv(inputFile)
cleanTweet <- tweetCleaner(readFile$tweet)
newDataFrame <- createDataFrame(cleanTweet)
#Removing empty tweets and creating new clean data frame
newDataFrame <- newDataFrame[!(is.na(newDataFrame$tweet) | newDataFrame$tweet==""),]
newDataFrame <- createDataFrame(newDataFrame)
write.csv(newDataFrame, outputFile)
```
### Stop words Removal
*The researchers removed English stop words dictionary that is provided by the R library ‘tm’. English stop words such as ‘the’, ‘is’, ‘are’ are removed from the document. To remove Tagalog stop words, the researchers manually checked the data set’s texts using text frequencies. Tagalog stop words such as ‘sa’, ‘akin’, and ‘ko’ have been identified and removed from the data set as these words do not convey any sentiments.*

```
removeStopWords <- function(tweet) {
  
  cleanTweet <- tweet
  
  cleanTweet <- VectorSource(cleanTweet)
  cleanTweet <- VCorpus(cleanTweet)
  
  #remove extra numbers before stop words removal
  cleanTweet <- tm_map(cleanTweet, removeNumbers)
  
  #remove english stop words
  cleanTweet <- tm_map(cleanTweet, removeWords, stopwords("english"))
  
  #Read custom filipino stop words
  stopwords <- read.csv("Stopwords.csv", header = FALSE)
  stopwords <- as.character(stopwords$V1)
  stopwords <- c(stopwords, stopwords())
  
  #remove custom filipino stop words
  cleanTweet <- tm_map(cleanTweet, removeWords, stopwords)
  
  #https://stackoverflow.com/questions/38710286/how-to-save-tm-map-output-to-csv-file
  #Convert vector corpus to data frame
  cleanTweet<-data.frame(text=unlist(sapply(cleanTweet, `[`, "content")), stringsAsFactors=F)
  
  return(cleanTweet)
}

tweetCleaner <- function(tweet) { #remove any extra noise after stop words removal
  cleanTweet <- tweet
  
  #remove single letters
  cleanTweet <- gsub(pattern="\\b[A-z]\\b{1}", replace=" ", cleanTweet)
  
  #Remove laughs such as Lololol or hahaha patterns
  cleanTweet <- gsub("\\b(?:a*(?:ha)+h?|(?:l+o+)+l+)\\b", " ", cleanTweet)
  cleanTweet <- gsub("\\b(a*ha+h[ha]*|o?l+o+l+[ol]*)\\b", " ", cleanTweet)
  
  #Remove extra white space
  cleanTweet <- gsub("\\s+", " ", cleanTweet)
  
  #Remove leading and trailing white space
  cleanTweet <- gsub("^\\s+|\\s+$", "", cleanTweet)
  
  return(cleanTweet)
}

```
### Stemming
*The R library ‘tm’ provides Porter’s algorithm to stem a document, it is only limited to English words. English stemming is only used for the reason that there are only a few of public algorithms that focuses on outputting stemmed tagalog words.*

```
library(tm)

stem <- function(tweet) {
  
  cleanTweet <- tweet
  cleanTweet <- VectorSource(cleanTweet)
  cleanTweet <- VCorpus(cleanTweet)
  
  #stem document using porter stem algorithm
  cleanTweet <- tm_map(cleanTweet, stemDocument)
  
  #https://stackoverflow.com/questions/38710286/how-to-save-tm-map-output-to-csv-file
  #Convert vector corpus to data frame
  cleanTweet<-data.frame(text=unlist(sapply(cleanTweet, `[`, "content")), stringsAsFactors=F)
  
  return(cleanTweet)
}

tweetCleaner <- function(tweet) { #remove any extra noise after stemming
  cleanTweet <- tweet
  
  #remove single letters
  cleanTweet <- gsub(pattern="\\b[A-z]\\b{1}", replace=" ", cleanTweet)
  
  #Remove extra white space
  cleanTweet <- gsub("\\s+", " ", cleanTweet)
  
  #Remove leading and trailing white space
  cleanTweet <- gsub("^\\s+|\\s+$", "", cleanTweet)
  
  return(cleanTweet)
}

createDataFrame <- function(cleanTweet) {
  newDataFrame <- data.frame(tweet = c(cleanTweet))
  return(newDataFrame)
}

```

## Data Visualization
Data visualization refers to the representation of information and data through visual means. This involves using tools that enable the visual depiction of trends, anomalies, and patterns within the data, employing elements such as charts, graphs, and maps. Furthermore, it serves as a valuable resource for professionals and entrepreneurs to effectively communicate data to individuals who may not have a technical background.

```

library(tm)
library(e1071)
library(tidyverse)
library(rpart)
library(caret)
library(RTextTools)
library(SparseM)

#Import Library
data <- read.csv('input.csv', col.names = c("Sentiment", "Corpus"))
summary(data)
str(data)
table(data$Sentiment)

```
### Most Frequent Words
*The figures below are the visual representation of the top 20 most frequent words for the three candidates. It can be seen that the most frequent words that appear for the three candidates are their names. The figures also showed that the words "leni" and "bbm" are the most frequent words that appear among the graphs of the three candidates.*


```

#build corpus
library(tm)
corpus <- iconv(data$Corpus, to = "utf-8")
corpus <- Corpus(VectorSource(corpus))
inspect(corpus[1:5])

#term document matrix
tdm <- TermDocumentMatrix(corpus)
tdm
tdm <- as.matrix(tdm)
inspect(tdm[1:10, 1:20])

# Sort by decreasing value of frequency
tdm <- sort(rowSums(tdm),decreasing=TRUE)
tdm <- data.frame(word = names(tdm),freq=tdm)

# Display the top 20 most frequent words
head(tdm, 20)

# Plot the most frequent words
barplot(tdm[1:20,]$freq, las = 2, names.arg = tdm[1:20,]$word,
        col ="blue", main ="Top 20 Most Frequent Words (Candidate Name)",
        ylab = "Word frequencies")
```
![](images/B4.png)
![](images/B5.png)
![](images/B6.png)


### Word Clouds
*Preprocessed data analysis also includes the creation of a word cloud, also known as a text cloud. It is used in sentiment analysis as a virtual representation of text data. This stage also included the installation of packages such as the text mining package (tm) and the word cloud generator package (word cloud) to analyze texts and present the keywords as a word cloud. The bigger the words in the word cloud, the more frequently they occur in the corpus.*

```
#generate word cloud
set.seed(1234)
wordcloud(words = tdm$word, freq = tdm$freq, min.freq = 5,
          max.words=100, random.order=FALSE, rot.per=0.40, 
          colors=brewer.pal(8, "Dark2"))
```
![](images/B1.png)
![](images/B2.png)
![](images/B3.png)

```
#sentiment Analysis using NRC dictionary- based approach
#obtain sentiment scores
get_nrc_sentiment("happy")
get_nrc_sentiment("excitement")
get_nrc_sentiment("dumb")

s <- get_nrc_sentiment(review)

#combine text and sentiment column
review_sentiment<-cbind(tweets$tweet,s)
table(review_sentiment['positive'])

#analyze sentiments using the syuzhet package based on the NRC sentiment dictionary
emotions <- get_nrc_sentiment(tweets$tweet)
emo_bar <- colSums(emotions)
emo_sum <- data.frame(count=emo_bar, emotions=names(emo_bar))

#calculating sentiments using function calculate_sentiment.

head(emotions,10)

#bar plot for sentiment scores
barplot(colSums(s), col = rainbow(10), ylab = 'count', main = 'Sentiment Results (leni)')
```
![](images/B7.png)
![](images/B8.png)
![](images/B9.png)

```
#plot the count of words associated with 8 emotions, expressed as a percentage
barplot(
  sort(colSums(prop.table(s[, 1:8]))), 
  horiz = TRUE, 
  cex.names = 0.7, 
  las = 1, 
  main = "Emotion in Text ", xlab="Percentage"
)
```
![](images/B10.png)
![](images/B11.png)
![](images/B12.png)

### Sentiment Classification 
The manually annotated data will be used as the input for the machine learning classification techniques. The training and testing dataset with 8,852 instances will be used to evaluate the performance of the sentiment classification.

### Classification Algorithms 


```
inputFile <- "input.csv"
tweet <- read.csv(inputFile)

corpus = VCorpus(VectorSource(tweet$tweet))

#Remove infrequent terms
library(caTools)
frequencies = DocumentTermMatrix(corpus)
sparse = removeSparseTerms(frequencies, 0.99) 

#Function
convert_count <- function(x) {
  y <- ifelse(x > 0, 1,0)
  y <- factor(y, levels=c(0,1), labels=c("No", "Yes"))
  y
}


datasetNB <- apply(sparse, 2, convert_count)
dataset = as.data.frame(as.matrix(datasetNB))

dataset$Class = tweet$sentiment
str(dataset$Class)
prop.table(table(dataset$Class))
dataset_convert = dim(dataset)[2]
```

| negative | neutral | positive |
| -------- | ------- |------- |
|0.2158834| 0.1246046| 0.6595120|

```
#data split
set.seed(724318)
split = sample(2,nrow(dataset),prob = c(2/3, 1/3),replace = TRUE)
train_set = dataset[split == 1,]
test_set = dataset[split == 2,] 

train_set$Class = as.factor(train_set$Class)
test_set$Class = as.factor(test_set$Class)

prop.table(table(train_set$Class))
prop.table(table(test_set$Class)) #skewed to positive


```

### Model Training
Repeated cross validation techniques was also used as it has proven to increase the performance of each algorithm for this type of dataset. The split ratio for the training set will be two-thirds (2/3) of the total dataset and for the testing set, one-third (1/3) ratio will be used.

```
#Cross Validation
library(caret)
control <- trainControl(method="repeatedcv",  
                        number=10,
                        repeats=3)


#1. Naive Bayes Classifier Model
library(e1071)
system.time(classifier_nb <- naiveBayes(train_set, 
                                        train_set$Class, 
                                        laplace = 1,
                                        confusionMatrix(pr5, reference = Zoo_test$type),
                                        tuneLength = 5))
#Predictor + Confusion Matrix
nb_pred = predict(classifier_nb, type = 'class', newdata = test_set)
confusionMatrix(table(nb_pred, test_set$Class))

```
|nb_pred   | negative | neutral | positive| 
| -------- | ------- |------- |------- |
 | negative  |  645  |  0  |  0|
 | neutral  |  0  | 360   |  0|
|  positive | 0  |  0  |  1919|

```
#2. SVM Model
svm_classifier <- svm(Class~.,
                      data=train_set,
                      kernel="linear")
#Predictor + Confusion Matrix
svm_pred = predict(svm_classifier, test_set)
confusionMatrix(table(svm_pred, test_set$Class))
```

|svm_pred  | negative| neutral| positive|
| -------- | ------- |------- |------- |
|  negative |   107  |   7   |  59|
|  neutral   |   0|     0  |    0|
|  positive |   538   |  353  |  1860|

```
#3. Random Forest Classifier Model
library(randomForest)
rf_classifier = randomForest(x = train_set[-dataset_convert],
                             y = train_set$Class,
                             trControl = control,
                             tuneLength = 5,
                             ntree = 300)
#Predictor + Confusion Matrix
rf_pred = predict(rf_classifier, newdata = test_set[-dataset_convert])
confusionMatrix(table(rf_pred, test_set$Class))
```
|rf_pred  |  negative| neutral |positive|
| -------- | ------- |------- |------- |
|  negative   |  118  |  7   |   63|
 | neutral   |   1 |   0  |  1 |
 | positive  |  526   | 353   |  1855 |

 
```
#4. Decision Tree Model using CART
#URL https://www.kaggle.com/code/suzanaiacob/sentiment-analysis-of-the-yelp-reviews-data#Exploratory-Data-Analysis
#Uses different data frame and splitting of data
library(rpart)
library(rpart.plot)
tweet$positive = as.factor(tweet$sentiment == "positive")
corpus = VCorpus(VectorSource(tweet$text))
cart_sparse = as.data.frame(as.matrix(sparse))
colnames(cart_sparse) = make.names(colnames(cart_sparse))
cart_sparse$positive = tweet$positive

#Splitting of data
set.seed(72141)
split = sample.split(cart_sparse$positive, SplitRatio = 2/3)
cart_sparse$split = split
train_set1 = subset(cart_sparse, split==TRUE)
test_set1 = subset(cart_sparse, split==FALSE)

#Decision Tree CART Improved Model
cpGrid = expand.grid(.cp=seq(0.001, 0.01, 0.001))

train(positive ~ ., 
      data = train_set1, 
      method = "rpart", 
      trControl = control, 
      tuneGrid = cpGrid)

cart_predictor = rpart(positive ~ ., 
                       data=train_set1, 
                       method="class", 
                       cp= 0.001)
prp(cart_predictor)

#Predictor + Confusion Matrix
cart_predictor = predict(cart_predictor, newdata=test_set1, type="class")
confusionMatrix(table(cart_predictor, test_set1$positive))

```

|cart_predictor |FALSE| TRUE|
| -------- | ------- |------- |
| FALSE|   130 |  57 |
| TRUE  |  875| 1889|



### Average Results 
Based on the results, the model based on Naïve Bayes has the highest accuracy rate of 100% among other classifiers. It was followed by the Decision Tree with overfitting with 68.42% and the random forest with 67.48%. Lastly, SVM has the lowest accuracy rate of 67.27% among the four algorithms used for the given dataset. The results show that Nave Bayes is the best performing approach for classifying sentiments on the collected data set, with 100% accuracy, precision, recall, and F1 score.

|Classifier Model|Naïve Bayes|SVM |Random Forest|Decision Tree|
| -------- | ------- |------- |------- |------- |
|Accuracy |	100% | 67.27% | 67.48% | 68.42%|
|Precision| 100% | 96.925 | 96.66% | 97.07%|
|Recall | 100%|  67.61% | 67.85% |68.34%|
|F1 Score| 100%| 79.65%| 79.73%	| 80.21%|



## Conclusion 
*Text mining and sentimental analysis have enabled us to acquire, analyze, visualize and interpret data particularly during elections. <br />
*Manual annotation and preprocessing of data have also improved the ML algorithms which made it more efficient to classify the datasets. The result also shows that Naïve Bayes with a 100% accuracy rate was the most efficient and accurate ML approach among the other models.<br />
*The result also shows that Naïve Bayes with a 100% accuracy rate was the most efficient and accurate ML approach among the other models in classifying dataset. 
