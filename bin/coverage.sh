# Execute from the root folder as bin/coverage.sh

coverage run --source '.' --omit="venv/*" manage.py test
coverage html

echo "Opening coverage report in browser"
python -mwebbrowser htmlcov/index.html