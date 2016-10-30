# pytest-github

[![Build Status](https://img.shields.io/travis/jlaska/pytest-github.svg)](https://travis-ci.org/jlaska/pytest-github)
[![Coverage Status](https://img.shields.io/coveralls/jlaska/pytest-github.svg)](https://coveralls.io/r/jlaska/pytest-github)
[![Requirements Status](https://requires.io/github/jlaska/pytest-github/requirements.svg?branch=master)](https://requires.io/github/jlaska/pytest-github/requirements/?branch=master)
[![Version](https://img.shields.io/pypi/v/pytest-github.svg)](https://pypi.python.org/pypi/pytest-github/)
[![Downloads](https://img.shields.io/pypi/dm/pytest-github.svg)](https://pypi.python.org/pypi/pytest-github/)
[![License](https://img.shields.io/pypi/l/pytest-github.svg)](https://pypi.python.org/pypi/pytest-github/)
[![Supported Python Versions](https://img.shields.io/pypi/pyversions/pytest-github.svg)](https://pypi.python.org/pypi/pytest-github/)


# tcz
TC-Zee - Scapy-based library to create and manage TCP connection. Allows to send data over a TCP connection automatically keeping track of SEQ and ACK numbers, 3-way handshake and connection tear-down, maintaining the low level control provided by Scapy, when needed. The purpose of this project is to provide a convenient way to verify network component robustness and compliance to the standards at the different level of the ISO-OSI stack.

This component (also known as Integratio Web Server in its form supporting only trivial HTTP request)
is part of a bigger project, aimed to provide a tool for black-box testing of IoT devices.

The idea is to redirect HTTP(s) request to the Integratio Device running the TC-Zee engine,
so that the testing content is provided instead of the expected real content from the real server.
