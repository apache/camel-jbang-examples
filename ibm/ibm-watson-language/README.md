# IBM Watson Natural Language Understanding Examples

This example demonstrates how to use IBM Watson Natural Language Understanding (NLU) with Apache Camel to analyze text and extract insights like sentiment, emotions, entities, keywords, and concepts.

## Prerequisites

* IBM Cloud account with Watson Natural Language Understanding service instance
* IBM Cloud API key with access to Watson NLU

## Install Camel JBang

include::../install.adoc[see installation]

## Setup IBM Watson Natural Language Understanding

### Create Watson NLU Service Instance

1. Log in to [IBM Cloud Console](https://cloud.ibm.com)
2. Create a Watson Natural Language Understanding service instance
3. Go to the service credentials page
4. Create new credentials or use existing ones
5. Copy your API key

### Configure Service URL (Optional)

Watson NLU provides different endpoints for different regions:

* **US South**: `https://api.us-south.natural-language-understanding.watson.cloud.ibm.com`
* **US East**: `https://api.us-east.natural-language-understanding.watson.cloud.ibm.com`
* **EU GB (London)**: `https://api.eu-gb.natural-language-understanding.watson.cloud.ibm.com`
* **EU DE (Frankfurt)**: `https://api.eu-de.natural-language-understanding.watson.cloud.ibm.com`
* **Tokyo**: `https://api.jp-tok.natural-language-understanding.watson.cloud.ibm.com`
* **Sydney**: `https://api.au-syd.natural-language-understanding.watson.cloud.ibm.com`

For more information, see the [Watson NLU API documentation](https://cloud.ibm.com/apidocs/natural-language-understanding).

## Configuration

Edit the `application.properties` file and update your IBM Cloud API key:

```properties
watson.apiKey=<your-ibm-cloud-api-key>
# watson.serviceUrl=https://api.us-south.natural-language-understanding.watson.cloud.ibm.com
```

**Important**: Replace `<your-ibm-cloud-api-key>` with your actual IBM Cloud API key from the Watson NLU service credentials.

## Example 1: Sentiment Analysis

This integration analyzes text sentiment using Watson NLU every 30 seconds.

### How to run

```shell
camel run sentiment-analysis.camel.yaml application.properties
```

Or using the SNAPSHOT version:

```shell
jbang -Dcamel.jbang.version=4.16.0 camel@apache/camel run sentiment-analysis.camel.yaml ibm-watson-language-sink.kamelet.yaml application.properties
```

### What it does

The integration:
1. Triggers every 30 seconds (3 times total)
2. Analyzes the sentiment of a sample text
3. Logs the sentiment label (positive/negative/neutral) and score
4. Logs the detected language

### Expected Output

```text
Analyzing text: I love this product! It's absolutely amazing...
Sentiment: positive (Score: 0.95)
Detected Language: en
```

## Example 2: Comprehensive Analysis

This integration performs comprehensive text analysis including sentiment, emotions, entities, keywords, and concepts.

### How to run

```shell
camel run comprehensive-analysis.camel.yaml application.properties
```

Or using the SNAPSHOT version:

```shell
jbang -Dcamel.jbang.version=4.16.0 camel@apache/camel run comprehensive-analysis.camel.yaml ibm-watson-language-sink.kamelet.yaml application.properties
```

### What it does

The integration:
1. Triggers every 60 seconds (2 times total)
2. Analyzes text for:
   - **Sentiment** - Positive/negative/neutral sentiment with score
   - **Emotions** - Joy, anger, sadness, fear, disgust
   - **Entities** - People, companies, organizations, locations
   - **Keywords** - Important keywords and phrases
   - **Concepts** - High-level concepts
3. Logs the complete analysis results

### Expected Output

```text
=== Analysis Results ===
Sentiment: positive (Score: 0.87)
Language: en
Full Analysis Results: {
  "sentiment": {
    "document": {
      "score": 0.87,
      "label": "positive"
    }
  },
  "entities": [
    {"type": "Company", "text": "Apple Inc.", "relevance": 0.98}
  ],
  "keywords": [
    {"text": "profits", "relevance": 0.89},
    {"text": "artificial intelligence", "relevance": 0.85}
  ],
  ...
}
```

## Example 3: Text Analysis HTTP API

This integration exposes REST API endpoints for text analysis.

### How to run

```shell
camel run text-analysis-api.camel.yaml application.properties
```

Or using the SNAPSHOT version:

```shell
jbang -Dcamel.jbang.version=4.16.0 camel@apache/camel run text-analysis-api.camel.yaml ibm-watson-language-sink.kamelet.yaml application.properties
```

### Available Endpoints

The integration exposes three HTTP endpoints:

#### 1. Sentiment Analysis API

Analyzes sentiment and emotions of the provided text.

```shell
curl -X POST http://localhost:8080/analyze/sentiment \
  -H "Content-Type: text/plain" \
  -d "This is an amazing product! I'm so happy with my purchase."
```

**Response:**
```json
{
  "sentiment": {
    "document": {
      "score": 0.92,
      "label": "positive"
    }
  },
  "emotion": {
    "document": {
      "emotion": {
        "joy": 0.85,
        "sadness": 0.02,
        "fear": 0.01,
        "disgust": 0.01,
        "anger": 0.01
      }
    }
  },
  "language": "en"
}
```

#### 2. Entity Extraction API

Extracts entities and keywords from the text.

```shell
curl -X POST http://localhost:8080/analyze/entities \
  -H "Content-Type: text/plain" \
  -d "IBM Watson is located in Armonk, New York. The company develops AI solutions."
```

**Response:**
```json
{
  "entities": [
    {
      "type": "Company",
      "text": "IBM Watson",
      "relevance": 0.99,
      "count": 1
    },
    {
      "type": "Location",
      "text": "Armonk",
      "relevance": 0.85
    }
  ],
  "keywords": [
    {
      "text": "AI solutions",
      "relevance": 0.87
    }
  ],
  "language": "en"
}
```

#### 3. Comprehensive Analysis API

Performs complete analysis including sentiment, emotions, entities, keywords, and concepts.

```shell
curl -X POST http://localhost:8080/analyze/all \
  -H "Content-Type: text/plain" \
  -d "Apple announced groundbreaking AI technology that will revolutionize healthcare."
```

**Response:**
```json
{
  "sentiment": {"document": {"score": 0.78, "label": "positive"}},
  "emotion": {"document": {"emotion": {"joy": 0.65, ...}}},
  "entities": [{"type": "Company", "text": "Apple", ...}],
  "keywords": [{"text": "AI technology", "relevance": 0.92}, ...],
  "concepts": [{"text": "Artificial intelligence", "relevance": 0.89}, ...],
  "language": "en"
}
```

### Testing the API

You can also test with longer text:

```shell
curl -X POST http://localhost:8080/analyze/sentiment \
  -H "Content-Type: text/plain" \
  -d @sample-text.txt
```

## Developer Web Console

You can enable the developer console via `--console` flag:

```shell
camel run text-analysis-api.camel.yaml ibm-watson-language-sink.kamelet.yaml application.properties --console
```

Then browse to http://localhost:8080/q/dev to introspect the running Camel application.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
