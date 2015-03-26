Per-client outgoing traffic limiter.

Purpose:
	keep the total outgoing traffic limited
	without limiting the connection speed of legitimate users.

This is a UNIX daemon that:
1) tracks all outgoing packages (via tcpdump),
2) calculates the usage of outgoing bandwidth for every client IP,
3) checks whether any clients exceed the limits (as defined in limittraf.conf),
4) takes actions (such as iptables ban) towards the misbehaving clients.

See README.USAGE for details.

_______________________________________________________________________________

NOTE: although the daemon itself is complete,
the only supported action is logging (LIMITTRAF_ACTION_LOG).

In order to actually ban someone, other actions (e.g. LIMITTRAF_ACTION_LIMIT
or LIMITTRAF_ACTION_BAN) must be implemented in action.c/TakeAction().

_______________________________________________________________________________

I wrote this in early 2013, when I was considering various ideas for my thesis
at the university. Because I selected another project, this one was abandoned
due to the lack of time, even though it was very close to completion
(only the actions still need to be implemented).

Published in 2015 (found this while looking through my code archives).

--
Edward Chernenko
