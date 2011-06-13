TODO
----

* TLS encryption for remote syslog.
* Automatically set up DNS / Elastic IP / ELB?
* Code is a bit of a mess, could do with more cleanup.
* The bootstrap script (installs Ruby, RubyGems etc) would probably be better
  off separated out into its own script.
* CloudWatch calls to create alarms (at setup time) and push metric data (every
  2 minutes) use the CloudWatch command-line tools, which are written in Java
  and spawn a new JVM for every API request, which is unnecessarily slow and
  memory-hungry.  Replace these with calls directly from Ruby (maybe use the
  [`right_aws`](http://rubygems.org/gems/right_aws) gem once its CloudWatch
  wrapper supports the new mon-put-data and mon-put-metric-alarm calls).
