# Cardpliance

This is the repository that hosts the source code for Cardpliance.

## What is Cardpliance

Cardpliance is a tool to detect PCI DSS noncompliance in android applications. It is built on top of a static analysis tool [Amandroid](http://pag.arguslab.org/argus-saf), also known as Argus-SAF. It leverages data flow analysis of Amandroid to generate data dependency graphs of these android applications and apply relevant logic to find out PCI DSS vulnerabilities. 

So far 6 PCI DSS rules are checked in Cardpliance. They are:    
1. Application persisting Credit card number.  
2. Applications persisting CVC.  
3. Applications not properly masking Credit Card number while displaying it.  
4. Applications not obfuscating Credit Card number before storing it.  
5. Applications not using proper SSL to transmit Credit Card data to open network.  
6. Applications not securely transmitting Credit Card data to other applications.  

Most of the checks in Cardpliance are done by taint tracking Credit Card information provided to the application through Graphical User Interface(i.e TextFields). Therefore we need to provide Cardpliacne a list of relevant Textfield resource identifiers corresponding to input textfields that take credit card information as input. To do that we reply on an open source tool [UiRef](https://github.com/wspr-ncsu/UiRef)run Cardpliance we first need to provide


## Publication

Full information on how Cardpliance works can be found on our academic paper that was accepted at 29th USENIX Security Symposium.   

Samin Yaseer Mahmud, Akhil Acharya, Benjamin Andow, William Enck, and Bradley Reaves. Cardpliance: PCI DSS Compliance of Android Applications. In Proceedings of the 29th USENIX Security Symposium (SECURITY), August 2020, Boston, MA, USA. [\[PDF\]](https://www.usenix.org/system/files/sec20fall_mahmud_prepub.pdf)

