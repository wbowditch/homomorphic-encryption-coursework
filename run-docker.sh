#!/bin/bash
docker run -it --mount type=bind,source="$(pwd)"/benchmark,target=/src/app  bowditch-coursework
