# ampt-monitor-zeek
AMPT Monitor plugin to read healthcheck signature notices from Zeek logs.

See [AMPT][ampt] for more information on the AMPT framework and the problems
it solves.

**ampt-monitor-zeek** is a plugin for [ampt-monitor][ampt_monitor], the event
reporting component in the AMPT framework. It monitors Zeek signature logs to
extract alert data for healthcheck probes and passes the data to ampt-monitor
for delivery to the AMPT manager.

## Installation and usage
See the [Wiki][wiki] for further documentation.


[ampt]: https://github.com/nids-io/ampt-manager/wiki/AMPT
[ampt_monitor]: https://github.com/nids-io/ampt-monitor
[wiki]: https://github.com/nids-io/ampt-monitor/wiki/
[zeek]: https://zeek.org/
