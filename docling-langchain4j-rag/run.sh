#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run the Docling + LangChain4j RAG example

jbang -Dcamel.jbang.version=4.16.0-SNAPSHOT camel@apache/camel run \
  --fresh \
  --dep=camel:docling \
  --dep=camel:langchain4j-chat \
  --dep=camel:platform-http \
  --dep=dev.langchain4j:langchain4j:1.6.0 \
  --dep=dev.langchain4j:langchain4j-ollama:1.6.0 \
  --properties=application.properties \
  docling-langchain4j-rag.yaml
