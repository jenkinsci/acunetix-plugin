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

1.  -   Plugin retrieve only first 100 targets
    -   Scans can now be executed on the online version of the scanner
    -   Reports cannot be downloaded. Now links to the reports will be
        provided on the output.  

##  Version 1.2.1 (January 10, 2019)

      Bug fixes:

1.  -   Fixed 429 error when pairing with online build

##  Version 1.2.2 (January 18, 2019)

      Bug fixes:

1.  -   Fixed 429 error for reports

##  Version 1.2.3 (February 06, 2019)

      Bug fixes:

1.  -   Saved API URL is not loaded and shown in Jenkins system page

##  Version 1.2.5 (February 14, 2020)

1.  -   Compatibility with Acunetix version 13
    -   New feature: incremental scans