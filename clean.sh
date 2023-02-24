#!/bin/bash
tc qdisc del dev eth0 clsact
tc filter del dev eth0 egress
