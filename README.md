# Cardpliance

Cardpliance is a tool to detect PCI DSS noncompliance in android applications. It is built on top of a static analysis tool [Amandroid](http://pag.arguslab.org/argus-saf), also known as Argus-SAF. It leverages data flow analysis of Amandroid to generate data dependency graphs of these android applications and apply relevant logic to find out PCI DSS vulnerabilities. 

So far 6 PCI DSS rules are checked in Cardpliance. They are:
-Application persisting Credit card number
-Applications persisting CVC
-Applications not properly masking Credit Card number while displaying it
-Applications not obfuscating Credit Card number before storing it
-Applications not using proper SSL to transmit Credit Card data to open network
-Applications not securely transmitting Credit Card data to other applications

