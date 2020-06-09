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

## How to run Cardpliance

You can clone the repo and build the project using build.sbt or you can download the pre built jar file and run it using the following command

java -jar cardpliance.jar t <apk directory> -a COMPONENT_BASED -mo CUSTOM_ANALYSIS -urcc <CC id file directory> -urcvc <CVC id file directory> -disp <CC displaying id file directory> -o <Output directory>

Here the options are as follows:

-a sets the approach to COMPONENT_BASED.   
-mo sets the module to CUSTOM_ANALYSIS. This reads our CustomSourcesAndSinks.txt file to build the source sink list.   
-urcc This is the location of the .txt file that has the resource identifier of textfields that take Credit card number as input.   
-urcvc This is the location of the .txt file that has the resource identifier of textfields that take CVC as input.    
-disp This is the location of the .txt file that has the resource identifier of textfields that displays Credit card number.    
-o this is the ourput directory where output is generated.    
    
For example

java -jar cardpliance.jar t APK/com.test.apk -a COMPONENT_BASED -mo CUSTOM_ANALYSIS -urcc IDS/CC/com.cctest.txt -urcc IDS/CVC/com.cvctest.txt -disp IDS/MASK/com.disp.txt -o /output

As you can see there are several text files that are required by Cardpliance as input. Most of the checks in Cardpliance are done by taint tracking Credit Card information provided to the application through Graphical User Interface(i.e TextFields). Therefore we need to provide Cardpliacne a list of relevant Textfield resource identifiers corresponding to input textfields that take credit card information as input. To do that we rely on an open source tool [UiRef](https://wspr.csc.ncsu.edu/uiref/). Details on how to run UiRef can be found on [this](https://github.com/wspr-ncsu/UiRef) link. UiRef outputs .XML laypouts resolving semantics of its user interfaces. Relavant Resource ID from these XML layouts can be extracted using the scripts provided in \cardpliance_scripts.


## Publication

Full information on how Cardpliance works can be found on our academic paper that was accepted at 29th USENIX Security Symposium.   

Samin Yaseer Mahmud, Akhil Acharya, Benjamin Andow, William Enck, and Bradley Reaves. Cardpliance: PCI DSS Compliance of Android Applications. In Proceedings of the 29th USENIX Security Symposium (SECURITY), August 2020, Boston, MA, USA. [\[PDF\]](https://www.usenix.org/system/files/sec20fall_mahmud_prepub.pdf)

## Licence

Details about the licence can be found on LICENCE.txt
