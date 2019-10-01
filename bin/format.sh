# Automatically formats code using black
# - Assumes you have installed black using pip install black
# - Assumes you are running from the root directory 
# 
# Invoke as bin/format.sh

black --exclude venv .
