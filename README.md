# CS4160 project

## Running test suite

The test suite creates some temporary directories (resulting from our attempt at the persisted storage bonus assignment). We created a bash script to conveniently delete these directories after running the tests. To run tests, run any of the following commands (replacing arguments with tests that actually exist):

```bash
bash run_tests.sh # Runs all tests following tests/*_tests.py naming pattern, like `python -m unittest discover -s tests -p "*_tests.py"

bash run_tests.sh tests.testfile_tests # Runs all tests in tests/testfile_tests.py

bash run_tests.sh tests.testfile_tests.ClassTests # Runs all tests in the class ClassTests, in the file tests/testfile_tests.py

bash run_tests.sh tests.testfile_tests.ClassTests.specific_test # Runs the test specific_test in class ClassTests, in the file tests/testfile_tests.py
```
