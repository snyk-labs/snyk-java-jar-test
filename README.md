# snyk-java-jar-test

## Getting Started
You will need Python 3.7 and [pipenv](https://pipenv.readthedocs.io/en/latest/).

```
git clone https://github.com/snyk-samples/snyk-java-jar-test.git
cd snyk-java-jar-test
pipenv install
pipenv shell
```

You will need to authorize your [Snyk CLI](https://github.com/snyk/snyk#installation).

## Usage
After activating an appropriate Python shell, you can do things like:

Test a single JAR in the local directory:
```
python snykjar.py gson-2.3.1.jar
```

Test a multiple specific JARs in the local directory:
```
python snykjar.py gson-2.3.1.jar commons-collections-3.2.1.jar jackson-core-2.9.8.jar
```

Test a single JAR in an arbitrary directory:
```
python snykjar.py /path/to/jars/gson-2.3.1.jar
```

Test multiple JARs in arbitrary directories:
```
python snykjar.py /path/to/jars/gson-2.3.1.jar /path/to/jars/commons-collections-3.2.1.jar /some/other/path/to/jars/jackson-core-2.9.8.jar
```

Test all the JARs in the current directory:
```
python snykjar.py .
```

Test a directory full of JARs:
```
python snykjar.py /path/to/jars
```

## Additional Parameters
`--jsonOutput=<output-file.json>` - this will save the output in a JSON file which is ideal for parsing.

`--orgId` - you only need to use this if your default organization in Snyk is not an organization that has API access. In most cases you won't need to use this. You can see your default Snyk organization by going to [Account Settings->Preferred Organization](https://app.snyk.io/account).

`--outputPom=<path/to/output/pom.xml>` - use this if you just want to get a `pom.xml` generated as output with all the detected Java packages. If you use this option, you the detected packages will not be tested and you will not get JSON output even if you use the `--jsonOutput` option. You might want to use this option to generate a `pom.xml` and then either test it with the snyk CLI (ex `snyk test --file=pom.xml`) or push the list of detected Java packages into Snyk and test monitor them there using `snyk monitor --file=pom.xml --project-name=<my-java-jars-test>`. For this to work, the filename needs to be `pom.xml`.
