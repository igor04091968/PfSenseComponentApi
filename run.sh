#!/bin/bash
jq 'walk(if type == "object" and has("allOf") then del(.allOf) else . end)' openapi.json > openapi_new.json
./mopenapi openapi_new.json openapipf -c --DestinationFolder ./
