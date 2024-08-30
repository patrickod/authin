document.addEventListener('DOMContentLoaded', async function () {
    const registerForm = document.getElementById('register')
    if (registerForm) {
        const submitButton = registerForm.querySelector('button[type="submit"]')
        if (submitButton) {
            submitButton.addEventListener('click', async function (event) {
                event.preventDefault()

                const formData = new FormData(registerForm)
                const data = {}
                formData.forEach((value, key) => {
                    data[key] = value
                })

                await fetch('/v1/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams(data).toString()
                })
                    .then(async response => {
                        let r = await response.json();
                        // convert the following base64 strings to ArrayBuffer
                        r.options.publicKey.challenge = bufferDecode(r.options.publicKey.challenge);
                        r.options.publicKey.user.id = bufferDecode(r.options.publicKey.user.id);
                        r.user_id = bufferDecode(r.user_id);

                        return navigator.credentials.create(r.options)
                    })
                    .then(credential => {
                        return fetch('/v1/register/finish', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                id: credential.id,
                                rawId: bufferEncode(credential.rawId),
                                type: credential.type,
                                response: {
                                    attestationObject: bufferEncode(credential.response.attestationObject),
                                    clientDataJSON: bufferEncode(credential.response.clientDataJSON),
                                },
                            })
                        });
                    })
                    .catch(error => {
                        console.error('Error:', error)
                    })
            });
        }
    }

    const loginForm = document.getElementById('login')
    if (loginForm) {
        const submitButton = loginForm.querySelector('button[type="submit"]')
        if (submitButton) {
            submitButton.addEventListener('click', async function (event) {
                event.preventDefault()

                await fetch('/v1/login')
                    .then(async (res) => {
                        let credentialRequestOptions = await res.json();
                        credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
                        if (credentialRequestOptions.publicKey.allowCredentials) {
                            credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
                                listItem.id = bufferDecode(listItem.id)
                            });
                        }

                        return navigator.credentials.get({
                            publicKey: credentialRequestOptions.publicKey
                        })
                    })
                    .then((assertion) => {
                        return fetch('/v1/login/finish', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                id: assertion.id,
                                rawId: bufferEncode(assertion.rawId),
                                type: assertion.type,
                                response: {
                                    authenticatorData: bufferEncode(assertion.response.authenticatorData),
                                    clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                                    signature: bufferEncode(assertion.response.signature),
                                    userHandle: bufferEncode(assertion.response.userHandle),
                                },
                            }),
                        })
                    })
                    .then((res) => {
                        if (res.status == 200) {
                            alert("successfully logged in !")
                            window.location.href = "/";
                        }
                    })
                    .catch((error) => {
                        alert("failed to register")
                    })
            });
        }
    }
});

function bufferDecode(value) {
    let v = value.replaceAll('-', '+').replaceAll('_', '/');
    return Uint8Array.from(atob(v), c => c.charCodeAt(0));
}

function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}
