// Package protocol provides ...
package protocol

import "text/template"

// Session session manager
type Session interface {
	AllowedOrigin() string
	SessionExpiresIn(cookie string) int
}

const checkSessionTemplate = `<script src="https://cdn.bootcdn.net/ajax/libs/crypto-js/4.1.1/crypto-js.min.js" />
<script>
/* Retrieves a cookie value */
function getCookie(cname) {

    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i <ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

/* Handles check session window.postMessage */
function receiveMessage(event) {
    try {
        // event.data = "<client_id> <session_state>"
        var client_id = event.data.split(' ')[0];
        var session_state = event.data.split(' ')[1];
        var salt = session_state.split('.')[1];

        // if message comes an unexpected origin
		if (event.origin !== '{{.origin}}') {
            event.source.postMessage("error", event.origin);
            return;
		}
		let sid = getCookie("sid");
        if (sid === "") {
            // No cookie found, or cookie deleted / expired
            event.source.postMessage("changed", event.origin);
            return;
        }
        // Here, the session_state is calculated in this particular way,
        // but it is entirely up to the OP how to do it under the
        // requirements defined in this specification.
		var ss = CryptoJS.SHA256(client_id + ' ' + event.origin + ' ' +
          sid + ' ' + salt) + "." + salt;

        let state = 'changed';
        if (session_state === ss) {
		    state = 'unchanged';
        } 
        event.source.postMessage(state, event.origin);
    } catch (e) {
        console.log("Check session error: " + event);
        event.source.postMessage("error", event.origin);
    }
}

window.addEventListener("message", receiveMessage, false);
</script>`

// CheckSessionIframe check session endpoint iframe
var CheckSessionIframe *template.Template

func init() {
	var err error
	CheckSessionIframe, err = template.New("check_session").Parse(checkSessionTemplate)
	if err != nil {
		panic(err)
	}
}
