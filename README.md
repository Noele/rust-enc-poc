
This is my first Rust application, a simple CLI file-encryption tool utilizing sodiumoxide's privatebox.

This was written as a POC for Discord in 6 hours with only two days of experience in Rust.

I chose encryption as my proof-of-concept task to address the statement <i>"[a] working knowledge of modern & frequently used (not necessarily the same, sadly) cryptographic primitives."</i> I chose <b>sodiumoxide</b>, but more specifically, its <b>privatebox</b> implementation <b>(xsalsa20poly1305)</b> as it is used by Discord in-house for voice encryption. 

<b>Usage:</b>
<pre>
  ./app file_to_encrypt file_password -e
  ./app file_to_decrypt file_password -d</pre>
  
Originally, I was going to use RSA for this task instead, but opted for sodiumoxide due to it's renown in the Rust community. This tool is indefinitely not production-ready.
<ul>
  Potential additions 
  <li>password signatures (hash of the password); used to verify password legitimacy before attempting decryption</li>
  <li>a new outfile for the encrypted payload, with a custom extension to "verify" that it is encrypted.</li>
  <li>implement curve25519xsalsa20poly1305 as an encryption/decryption method, for increased integrity</li>
</ul>
