Secure Password Storage Proof of Concept
========================================

This is a basic proof of concept around increasing the complexity of password storage.

Background
----------

Many organizations have had their password databases stolen. In many cases they passwords were in plain text;
however, in other situations the password were encrypted using standard system methodologies. The problem is
those seeking to use the password databases against the organizations have already generated great amounts of
data with many passwords already listed in what is known as "Rainbow Tables".

With "Rainbow Tables" one simply takes the hashes password entry and does a lookup to find a value that will
reliably generate that hash. These are built for numerous different standardized password storage systems,
such as those implemented by Windows, Linux, and Mac.

Concept
-------

Since systems are highly standardized, the goal here is to give administrators a means to introduce custom
variances by defining their own rule sets. Rule sets include hashes and how to use them. This scheme is
entirely backwards compatible as the original means would be to use the original hash algorithm without
any modifications. Additional security capability would then be added by mutating the input and output
of the default hash and/or adding more hashers.

A means of calculating the strength of the rule set would be necessary to help administrators ensure they
are using secure means.
