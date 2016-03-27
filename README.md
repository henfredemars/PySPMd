# PySPMd
Python daemon and client library implementing a variant of the Schematic Protection Model (SPM)

# Notable Differences
* Objects use a virtual directory-based model (instead of name, object has a path)
* Superusers are not required to obey the model
* Rights not enforced by the daemon, only recorded and reported

# Notable Contents

```
docs/
	Class documentation associated with the project in its infancy
spicy.py
	Interactive command interpreter for server administration
SPM/
	Primary project python module. Contains Client and Server objects
TestClient.py
	Simple client-side testing of basic server behavior
TestServer.py
	Simple server launcher and basic test script
```

This client-server SPM implementation is under development.
Most testing is performed manually via the interpreter, but should be automated.
