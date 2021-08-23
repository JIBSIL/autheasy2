# autheasy2
(not yet) Plug-and-play authentication for Express. Integrate with your app in seconds. A modern revision of https://github.com/pranjaldatta/AuthEasy

## What?
AuthEasy is a response to the problem that people have in nearly every website: authentication. It comes with these features:
- Customizable rate-limiting so malicious users can't make too many accounts
- bcrypt protection: irreversable encryption that protects users' passwords
- Cookie authentication with industry-standard JWT tokens, with customizable session expiry times
- Email verification codes

## Why?
AuthEasy2 was made because it's too hard to make authentication.

Some people use services like Auth0 or Okta to authenticate users, but above a certain quota, they ask for payment. What if these services went offline, or were subject to a hack or DDOS attack? Your user accounts could be compromised as a result.

Plug-and-play authentication is very hard to find for free. That's where AuthEasy2 comes in.

In seconds, you can deploy AuthEasy2 to a free cloud server from Heroku. Or, you can self-host on your own server. All code is public and open-source, because we prioritize security.
