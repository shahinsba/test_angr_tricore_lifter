# test_angr_tricore_lifter

This repository contains modules to test the angr tricore lifter from [angr/angr-platforms](https://github.com/angr/angr-platforms) repository.
The *test.py* reads test cases from *testcases.yaml* and then executes the hex code by angr.
The tricore hex code will be translated by tricore lifter in background.

This module requires angr and angr-platforms that can be installed as following:
- sudo pip install angr-utils
- git clone https://github.com/angr/angr-platforms.git
- cd angr-platforms
- python3 setup.py build
- sudo python3 setup.py install
