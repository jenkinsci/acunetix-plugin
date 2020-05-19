#  Changelog

##  Version 1.0.0 (March 15, 2017)

1.  Initial release
2.  New features
    1.  Trigger Acunetix scans from within Jenkins upon each build
    2.  Trigger Acunetix scans with built-in or custom Scan Types to
        only scan for specific vulnerabilities
    3.  Configure Jenkins to fail a build (and optionally abort the
        scan) as soon as a specific threat-level (high, medium or low
        severity) is reached
    4.  Automatically generate reports and save them within Jenkins
3.  Improvements
    1.  N/A
4.  Bugfixes
    1.  N/A

##  Version 1.1.0 (October 24, 2018)

      Improvements: Use Jenkins credentials for storing the API Key

##  Version 1.2.0 (October 25, 2018)

      Improvements: Better exception handling like situations when
configured target or profile have been deleted in main application

      Bug fixes:

 -   Plugin retrieve only first 100 targets
 -   Scans can now be executed on the online version of the scanner
 -   Reports cannot be downloaded. Now links to the reports will be
        provided on the output.  

##  Version 1.2.1 (January 10, 2019)

      Bug fixes:

 -   Fixed 429 error when pairing with online build

##  Version 1.2.2 (January 18, 2019)

      Bug fixes:

 -   Fixed 429 error for reports

##  Version 1.2.3 (February 06, 2019)

      Bug fixes:

 -   Saved API URL is not loaded and shown in Jenkins system page

##  Version 1.2.5 (February 14, 2020)

  -   Compatibility with Acunetix version 13
  -   New feature: incremental scans

##  Version 1.2.6 (February 26, 2020)

  -   Save reports in workspace
  -   Improved logging
  
##  Version 1.2.8 (April 21, 2020)

  -   Fixed compatibility with online version
  -   Fix: report was generated even when the scan could not be performed 
  -   Specific error when the target was deleted and plugin configuration was not updated
  -   Re-added report download link in console
  -   Report save to workspace configurable through a checkbox

##  Version 1.2.9 (May 19, 2020)  

  -   Provide all report templates when choosing for a report type. Before were available only standard reports
