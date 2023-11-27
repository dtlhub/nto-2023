#!/usr/bin/env sh

socat tcp-listen:1489,reuseaddr,fork exec:"./chall"
