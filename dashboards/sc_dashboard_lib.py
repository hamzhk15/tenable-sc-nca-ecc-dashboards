#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared library for generating Tenable Security Center dashboard XML.

Emits <definition> blocks as base64(PHP-serialized) exactly as SC expects,
using only query constructs (tools, filters, output types, colors, table
columns) proven to work in the customer's existing dashboards.
"""
import base64
from xml.sax.saxutils import escape

# ---- PHP serialization (byte-length prefixed, SC format) ------------------
def ser(obj):
    if isinstance(obj, str):
        return 's:%d:"%s";' % (len(obj.encode("utf-8")), obj)
    if isinstance(obj, dict):
        return "a:%d:{" % len(obj) + "".join(ser(k) + ser(v) for k, v in obj.items()) + "}"
    if isinstance(obj, list):
        return "a:%d:{" % len(obj) + "".join("i:%d;" % i + ser(v) for i, v in enumerate(obj)) + "}"
    raise TypeError(type(obj))

def b64(obj):
    return base64.b64encode(ser(obj).encode("utf-8")).decode("ascii")

# ---- colors: foreground:background (proven-rendering palette) -------------
C_NEUTRAL = "000000:ffffff"   # black on white
C_GREEN   = "ffffff:79ab3d"
C_RED     = "ffffff:dd4b50"
C_AMBER   = "000000:f8c851"
C_BLUE    = "ffffff:2c87d6"
C_PURPLE  = "ffffff:77619d"
C_ORANGE  = "000000:f18c43"   # black on orange (escalation tier between amber & red)

# ---- severity codes -------------------------------------------------------
CRIT, HIGH, MED, LOW, INFO = "4", "3", "2", "1", "0"

# ---- query / cell builders ------------------------------------------------
_qc = [0]
def _qname():
    _qc[0] += 1
    return "_1750000000.%04d_%d_1_1" % (_qc[0], _qc[0])

def flt(name, value, op="="):
    return {"filterName": name, "operator": op, "value": value}

def datasource(tool, filters, source="cumulative", result="single",
               sort_col="", sort_dir="", qtype="vuln", qname=None):
    # SC names queries per-component: matrix cells "_<ts>_<cellSeq>_1_1",
    # tables "_<ts>_table_1_1". A global counter (the old behaviour) produced
    # names SC didn't expect, leaving widgets stuck "loading" until re-saved.
    return {
        "querySourceType": source, "querySourceID": "", "querySourceView": "all",
        "sortColumn": sort_col, "sortDirection": sort_dir, "iteratorID": "-1",
        "context": "dashboard", "resultStyle": result,
        "query": {
            "name": qname if qname is not None else _qname(),
            "description": "", "tool": tool, "type": qtype,
            "tags": "", "context": "dashboard", "browseColumns": "",
            "browseSortColumn": "", "browseSortDirection": "ASC",
            "ownerGID": "0", "targetGID": "-1", "filters": filters, "groups": [],
        },
    }

def cell(seq, tool, filters, colors, source="cumulative", out_text="vulnCount",
         qtype="vuln"):
    return {
        "sequence": str(seq),
        "dataSource": datasource(tool, filters, source=source, qtype=qtype,
                                 qname="_1750000000.%04d_%d_1_1" % (seq, seq)),
        "baseDataSource": [],
        "conditionals": [{
            "conditionalName": "default", "conditionalOperator": "=",
            "conditionalValue": "", "outputType": "textCount",
            "outputColors": colors, "outputText": out_text,
        }],
    }

def matrix(title, row_labels, col_labels, cell_specs, base_cluster=2000):
    """cell_specs row-major: (tool, filters, colors[, source[, out_text[, qtype]]])."""
    rows = len(row_labels)
    cells = []
    for seq, spec in enumerate(cell_specs, start=1):
        tool, filters, colors = spec[0], spec[1], spec[2]
        source = spec[3] if len(spec) > 3 else "cumulative"
        out_text = spec[4] if len(spec) > 4 else "vulnCount"
        qtype = spec[5] if len(spec) > 5 else "vuln"
        cells.append(cell(seq, tool, filters, colors, source, out_text, qtype))
    clusters = [{"id": str(base_cluster + i), "strips": str(i + 1),
                 "schedule": "FREQ=DAILY;INTERVAL=1"} for i in range(rows)]
    return {
        "styleID": "-1", "cells": cells, "rows": str(rows),
        "columns": str(len(col_labels)), "title": title, "stripType": "column",
        "rowLabels":    [{"sequence": str(i + 1), "text": t} for i, t in enumerate(row_labels)],
        "columnLabels": [{"sequence": str(i + 1), "text": t} for i, t in enumerate(col_labels)],
        "clusters": clusters,
    }

def table(columns, tool, filters, data_points=10, sort_col="score",
          sort_dir="desc", source="cumulative"):
    return {
        "styleID": "-1", "columns": [{"name": c} for c in columns],
        "dataPoints": str(data_points), "displayDataPoints": str(data_points),
        "dataSource": datasource(tool, filters, source=source, result="list",
                                 sort_col=sort_col, sort_dir=sort_dir,
                                 qname="_1750000000.0001_table_1_1"),
    }

# ---- dashboard assembly ---------------------------------------------------
def write_dashboard(filename, name, description, components):
    """components: list of dicts {name, desc, kind, column, order, definition}."""
    p = ['<?xml version="1.0" encoding="UTF-8"?>', "<dashboardTab>",
         "\t<scVersion>6.2.0</scVersion>",
         "\t<name>%s</name>" % escape(name),
         "\t<description>%s</description>" % escape(description),
         "\t<numColumns>2</numColumns>",
         "\t<columnWidths>", "\t\t<column>50</column>", "\t\t<column>50</column>",
         "\t</columnWidths>", "\t<dashboardComponents>"]
    for c in components:
        p += ["\t\t<component>",
              "\t\t\t<name>%s</name>" % escape(c["name"]),
              "\t\t\t<description>%s</description>" % escape(c["desc"]),
              "\t\t\t<componentType>%s</componentType>" % c["kind"],
              "\t\t\t<type>%s</type>" % c["kind"],
              "\t\t\t<column>%d</column>" % c["column"],
              "\t\t\t<order>%d</order>" % c["order"]]
        if c["kind"] == "table":
            p.append("\t\t\t<schedule>FREQ=DAILY;INTERVAL=1</schedule>")
        p += ["\t\t\t<definition>%s</definition>" % b64(c["definition"]),
              "\t\t</component>"]
    p += ["\t</dashboardComponents>", "</dashboardTab>", ""]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(p))
    return filename
