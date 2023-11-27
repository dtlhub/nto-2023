#!/bin/sh
socat tcp-listen:869,reuseaddr,fork exec:"./heahoz"

