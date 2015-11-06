# sonar.js
A framework for identifying and launching exploits against internal network hosts. Works via WebRTC IP enumeration, WebSocket host scanning, and external resource fingerprinting.

## How does it work?
Upon loading the sonar.js payload in a modern web browser the following will happen:
* sonar.js will use WebRTC to enumerate what internal IPs the user loading the payload has, assuming a /24 subnet size unless a target subnet or subnet size has been specified.
* sonar.js then attempts to find live hosts on the internal network via WebSockets.
* If a live host is found, sonar.js begins to attempt to fingerprint the host by linking to it via ```<img src="x">``` and ```<link rel="stylesheet" type="text/css" href="x">``` and hooking the ```onload``` event. If the expected resources load successfully it will trigger the pre-set JavaScript callback to start the user-supplied exploit.

## Fingerprints
sonar.js works off of a database of fingerprints. A fingerprint is simply a list of known resources on a device that can be linked to and detected via ```onload```. Examples of this include images, CSS stylesheets, and even external JavaScript.

An example fingerprint database can be seen below:
```
var fingerprints = [
    {
        'name': "ASUS RT-N66U",
        'resources': ["/images/New_ui/asustitle.png","/images/loading.gif","/images/alertImg.png","/images/New_ui/networkmap/line_one.png","/images/New_ui/networkmap/lock.png","/images/New_ui/networkmap/line_two.png","/index_style.css","/form_style.css","/NM_style.css","/other.css"],
        'callback': function( ip ) {
            // Insert exploit here
        },
    },
    {
        'name': "Linksys WRT54G",
        'resources': ["/UILinksys.gif","/UI_10.gif","/UI_07.gif","/UI_06.gif","/UI_03.gif","/UI_02.gif","/UI_Cisco.gif","/style.css"],
        'callback': function( ip ) {
            // Insert exploit here
        },
    },
]
```

The above database contains fingerprints for two devices, the *ASUS RT-N66U* WiFi router and the *Linksys WRT54G* WiFi router.

Each database entry has the following:
* ``name``: A  field to identify what device the fingerprint is for. This could be something like *HP Officejet 4500 printer* or *Linksys WRT54G Router*.
* ```resources```: This is an array of relative links to resources such as CSS stylesheets, images, or even JavaScript files. If you expect these resources to be on a non-standard port such as ``8080``, set the resource with the port included: ```:8080/unique.css```. Keep in mind using external resources with active content such as JavaScript is dangerous as it can interrupt the regular flow of execution.
* ```callback```: If all of these resources are found to exist on the enumerated host then the ```callback``` function is called with a single argument of the device's IP address.

By creating your own fingerprints you can build custom exploits that will be launched against internal devices once they are detected by sonar.js. Common exploits include things such as Cross-site Request Forgery (CSRF), Cross-site Scripting (XSS), etc. The idea being that you can use these vulnerabilities to do things such as modifying router DNS configurations, dumping files from an internal fileserver, and more.

For an easier way to create fingerprints, see the following Chrome extension which generates fingerprint template code automatically for the page you're on:

<a href="https://chrome.google.com/webstore/detail/sonar.js-fingerprint-generat/pmijnndljolchjlfcncaeoejfpjjagef">Click Here to Install Chrome Extension</a>

![sonar.js fingerprint generator](https://i.imgur.com/LR1X4Py.png)

## What can be done using sonar.js?
By using sonar.js a pentesting team can build web exploits against things such as internal logging servers, routers, printers, VOIP phones, and more. Due to internal networks often being less guarded, attacks such as CSRF and XSS can be powerful to take over the configurations of devices on a hosts internal network. Did we mention this can all be done from an Internet webpage?

## Help us build our database!
If you have a device such as a printer, router, or some other internal service please submit a fingerprint to us so we can add it to our master database. We will be adding more fingerprints for more devices overtime but we are limited to the devices that we have access to.
