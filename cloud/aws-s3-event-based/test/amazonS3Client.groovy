/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.Collections;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.eventbridge.EventBridgeClient
import software.amazon.awssdk.services.eventbridge.model.Target
import software.amazon.awssdk.services.eventbridge.model.PutRuleResponse
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.EventBridgeConfiguration
import software.amazon.awssdk.services.sqs.SqsClient
import software.amazon.awssdk.services.sqs.model.CreateQueueResponse
import software.amazon.awssdk.services.sqs.model.QueueAttributeName

// Creates an AWS S3 client that is used in the test to push data to the bucket.
// Also creates and prepares the bucket as well as the SQS queue and EVENT_BRIDGE notifications.

S3Client s3 = S3Client
        .builder()
        .endpointOverride(URI.create('${CITRUS_TESTCONTAINERS_LOCALSTACK_S3_URL}'))
        .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_ACCESS_KEY}',
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_SECRET_KEY}')
        ))
        .forcePathStyle(true)
        .region(Region.of('${CITRUS_TESTCONTAINERS_LOCALSTACK_REGION}'))
        .build()

SqsClient sqsClient = SqsClient
        .builder()
        .endpointOverride(URI.create('${CITRUS_TESTCONTAINERS_LOCALSTACK_SQS_URL}'))
        .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_ACCESS_KEY}',
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_SECRET_KEY}')
        ))
        .region(Region.of('${CITRUS_TESTCONTAINERS_LOCALSTACK_REGION}'))
        .build()

EventBridgeClient eventBridgeClient = EventBridgeClient
        .builder()
        .endpointOverride(URI.create('${CITRUS_TESTCONTAINERS_LOCALSTACK_EVENTBRIDGE_URL}'))
        .credentialsProvider(StaticCredentialsProvider.create(
                AwsBasicCredentials.create(
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_ACCESS_KEY}',
                        '${CITRUS_TESTCONTAINERS_LOCALSTACK_SECRET_KEY}')
        ))
        .region(Region.of('${CITRUS_TESTCONTAINERS_LOCALSTACK_REGION}'))
        .build()

// Create bucket
s3.createBucket(b -> b.bucket('${aws.bucketNameOrArn}'))

// Enable EventBridge notification on the bucket
s3.putBucketNotificationConfiguration(b -> b.bucket('${aws.bucketNameOrArn}').notificationConfiguration(nb -> nb.eventBridgeConfiguration(EventBridgeConfiguration.builder().build())));

eventBridgeClient.createEventBus(b -> b.name("s3-events-cdc"))

// Add an EventBridge rule on the bucket
PutRuleResponse putRuleResponse = eventBridgeClient.putRule(b -> b.name("s3-events-cdc").eventPattern('''
{
  "source": ["aws.s3"],
  "detail": {
    "bucket": { 
      "name": [ "${aws.bucketNameOrArn}" ]
    }
  }
}
'''))

CreateQueueResponse createQueueResponse = sqsClient.createQueue(s -> s.queueName('${aws.queueNameOrArn}'))

// Modify access policy for the queue just created
String queueUrl = createQueueResponse.queueUrl()
String queueArn = 'arn:aws:sqs:${aws.region}:000000000000:${aws.queueNameOrArn}'

sqsClient.setQueueAttributes(b -> b.queueUrl(queueUrl).attributes(Collections.singletonMap(QueueAttributeName.POLICY, '{' +
  '"Version": "2012-10-17",' +
  '"Id": "' + queueArn + '/SQSDefaultPolicy",' +
  '"Statement":' +
  '[{ "Sid": "EventsToMyQueue", ' +
    '"Effect": "Allow", ' +
    '"Principal": {' +
    '"Service": "events.amazonaws.com"}, ' +
    '"Action": "sqs:SendMessage", ' +
    '"Resource": "' + queueArn + '", ' +
    '"Condition": {' +
        '"ArnEquals": {' +
          '"aws:SourceArn": "' + putRuleResponse.ruleArn() + '"' +
        '}' +
    '}' +
  '}]' +
'}')))

// Add a target for EventBridge Rule which will be the SQS Queue just created
eventBridgeClient.putTargets(b -> b.rule('s3-events-cdc').targets(Target.builder().id("sqs-sub").arn(queueArn).build()))

return s3
