function New-DllSuiteReport {
    <#
    .SYNOPSIS
        Render a self-contained HTML report from an Invoke-DllSuiteAnalysis
        result. The .html embeds CSS, JS and the analysis data as JSON, so
        it opens anywhere with no dependencies.

    .DESCRIPTION
        Takes the structured analysis object produced by
        Invoke-DllSuiteAnalysis (or its serialized JSON form) and writes a
        single HTML file. The page renders client-side from the embedded
        JSON, so filtering and table sorting work offline. Sections:

          - Summary (counters and scanned paths).
          - Duplicate groups (byte-identical DLLs).
          - GUID conflicts (drift highlighted).
          - Registration status of conflicted CoClasses.
          - Full DLL inventory.

        Designed to be the artifact you mail to the dev teams.

    .PARAMETER Analysis
        Analysis object as returned by Invoke-DllSuiteAnalysis. Pipeline-
        friendly. Mutually exclusive with -JsonPath.

    .PARAMETER JsonPath
        Path to a previously saved report.json (schema 'dllsuite/1').
        Useful in CI: scan once on the server, render the HTML on a
        different machine. Mutually exclusive with -Analysis.

    .PARAMETER OutputPath
        Destination .html file. Created or overwritten.

    .EXAMPLE
        Invoke-DllSuiteAnalysis -Path .\bin -Recurse |
            New-DllSuiteReport -OutputPath .\suite-report.html

    .EXAMPLE
        New-DllSuiteReport -JsonPath .\artifacts\report.json `
                           -OutputPath .\artifacts\report.html
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromObject')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromObject', ValueFromPipeline)]
        [psobject]$Analysis,

        [Parameter(Mandatory, ParameterSetName = 'FromJson')]
        [string]$JsonPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'FromJson') {
            $resolved = (Resolve-Path -LiteralPath $JsonPath -ErrorAction Stop).ProviderPath
            $jsonText = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
            $Analysis = $jsonText | ConvertFrom-Json
        } else {
            $jsonText = $Analysis | ConvertTo-Json -Depth 12
        }

        if (-not $Analysis -or -not $Analysis.Schema) {
            throw "Input does not look like a dllsuite/1 analysis object."
        }

        # Escape </script> in case any string field contained it (paranoia).
        $safeJson = $jsonText -replace '</script', '<\/script'

        $title = "DLL Suite Analysis - {0}" -f $Analysis.HostName

        # ---- CSS (single-quoted here-string -> no PS interpolation) ----
        $css = @'
*,*::before,*::after { box-sizing: border-box; }
html { font-size: 14px; }
body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #1f2328;
    background: #f6f8fa;
    line-height: 1.5;
}
header {
    background: #24292f;
    color: #fff;
    padding: 1.5rem 2rem;
    border-bottom: 4px solid #0969da;
}
header h1 { margin: 0 0 .5rem; font-size: 1.5rem; font-weight: 600; }
header .meta { display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: .85rem; opacity: .85; }
header .meta span { white-space: nowrap; }
main { max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem 4rem; }
section { background: #fff; border: 1px solid #d0d7de; border-radius: 6px; margin-bottom: 1.5rem; overflow: hidden; }
section > header { display: none; }
section h2 {
    margin: 0;
    padding: .9rem 1.25rem;
    font-size: 1.05rem;
    font-weight: 600;
    background: #f6f8fa;
    border-bottom: 1px solid #d0d7de;
    display: flex;
    align-items: center;
    gap: .6rem;
}
section h2 .count {
    background: #0969da;
    color: #fff;
    padding: .1rem .55rem;
    border-radius: 999px;
    font-size: .75rem;
    font-weight: 600;
}
section h2 .count.zero { background: #6a737d; }
section h2 .count.warn { background: #bf8700; }
section h2 .count.bad  { background: #cf222e; }
section .desc { padding: .75rem 1.25rem; font-size: .85rem; color: #57606a; border-bottom: 1px solid #d0d7de; }
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1px;
    background: #d0d7de;
}
.metric {
    background: #fff;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: .25rem;
}
.metric .v { font-size: 1.6rem; font-weight: 600; line-height: 1; }
.metric .l { font-size: .75rem; color: #57606a; text-transform: uppercase; letter-spacing: .04em; }
.metric.warn .v { color: #bf8700; }
.metric.bad  .v { color: #cf222e; }
.paths { padding: .75rem 1.25rem; font-size: .85rem; color: #57606a; border-top: 1px solid #d0d7de; }
.paths code { background: #f6f8fa; padding: .1rem .35rem; border-radius: 3px; margin-right: .35rem; }
.controls { padding: .75rem 1.25rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; border-bottom: 1px solid #d0d7de; }
.controls input[type="search"] {
    flex: 1 1 200px;
    padding: .35rem .6rem;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    font-size: .85rem;
    font-family: inherit;
}
.controls label { font-size: .85rem; cursor: pointer; user-select: none; display: flex; align-items: center; gap: .35rem; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
thead th { background: #f6f8fa; text-align: left; padding: .6rem 1.25rem; font-weight: 600; border-bottom: 1px solid #d0d7de; white-space: nowrap; }
tbody td { padding: .55rem 1.25rem; border-bottom: 1px solid #eaeef2; vertical-align: top; }
tbody tr:hover { background: #f6f8fa; }
tbody tr.hidden { display: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, 'Cascadia Code', Consolas, monospace; font-size: .82rem; }
.guid { color: #6f42c1; }
.path { color: #57606a; word-break: break-all; }
.badge { display: inline-block; padding: .12rem .5rem; border-radius: 3px; font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; line-height: 1.5; }
.badge.ok       { background: #dafbe1; color: #1a7f37; }
.badge.warn     { background: #fff8c5; color: #9a6700; }
.badge.bad      { background: #ffebe9; color: #cf222e; }
.badge.muted    { background: #eaeef2; color: #57606a; }
.badge.info     { background: #ddf4ff; color: #0969da; }
.kind-coclass  { color: #1a7f37; }
.kind-interface, .kind-dispatch { color: #0969da; }
.kind-enum, .kind-record, .kind-union, .kind-alias, .kind-module { color: #6e7781; }
ul.compact { margin: .25rem 0; padding-left: 1.25rem; }
ul.compact li { font-size: .82rem; color: #57606a; }
details summary { cursor: pointer; font-size: .82rem; color: #0969da; }
details[open] summary { margin-bottom: .35rem; }
.empty { padding: 2rem 1.25rem; color: #57606a; font-style: italic; text-align: center; }
footer { text-align: center; padding: 1.5rem; color: #57606a; font-size: .8rem; }
@media (max-width: 720px) {
    main { padding: 1rem; }
    header { padding: 1rem; }
    thead th, tbody td { padding: .5rem; }
}
'@

        # ---- JS (single-quoted here-string) ----------------------------
        $js = @'
(function () {
    var data = window.__SUITE_ANALYSIS__;
    if (!data) { document.body.innerHTML = '<p style="padding:2rem">No analysis data found.</p>'; return; }

    function el(tag, attrs, children) {
        var n = document.createElement(tag);
        if (attrs) for (var k in attrs) {
            if (k === 'class') n.className = attrs[k];
            else if (k === 'html') n.innerHTML = attrs[k];
            else if (k === 'text') n.textContent = attrs[k];
            else n.setAttribute(k, attrs[k]);
        }
        if (children) for (var i = 0; i < children.length; i++) {
            var c = children[i];
            if (c == null) continue;
            n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
        }
        return n;
    }
    function fmtBytes(n) {
        if (n == null) return '';
        if (n < 1024) return n + ' B';
        if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
        return (n/(1024*1024)).toFixed(2) + ' MB';
    }
    function shortHash(h) { return h ? h.substring(0, 12) : ''; }
    function basename(p) { return p ? p.replace(/^.*[\\\/]/, '') : ''; }

    // Build the page
    document.title = data.HostName + ' - DLL Suite Analysis';

    var root = document.getElementById('root');
    var s = data.Summary;

    // ----- Summary cards -----
    var cards = [
        { v: s.FilesScanned,     l: 'Files scanned' },
        { v: s.UniqueByHash,     l: 'Unique by hash' },
        { v: s.ComServers,       l: 'COM servers' },
        { v: s.DuplicateGroups,  l: 'Duplicate groups', cls: s.DuplicateGroups > 0 ? 'warn' : '' },
        { v: s.GuidConflicts,    l: 'GUID conflicts',   cls: s.GuidConflicts > 0  ? 'warn' : '' },
        { v: s.DriftIssues,      l: 'Drift issues',     cls: s.DriftIssues > 0    ? 'bad'  : '' },
        { v: s.ParseErrors,      l: 'Parse errors',     cls: s.ParseErrors > 0    ? 'bad'  : '' }
    ];
    var grid = el('div', { class: 'summary-grid' });
    cards.forEach(function (c) {
        grid.appendChild(el('div', { class: 'metric' + (c.cls ? ' ' + c.cls : '') }, [
            el('span', { class: 'v', text: String(c.v) }),
            el('span', { class: 'l', text: c.l })
        ]));
    });
    var pathsList = (data.ScannedPaths || []).map(function (p) {
        return el('code', { text: p });
    });
    var pathsDiv = el('div', { class: 'paths' });
    pathsDiv.appendChild(document.createTextNode('Paths: '));
    pathsList.forEach(function (c) { pathsDiv.appendChild(c); });
    var summary = section('Summary', null, null);
    summary.appendChild(grid);
    summary.appendChild(pathsDiv);
    root.appendChild(summary);

    // ----- Duplicate groups -----
    var dupSec = section('Duplicate groups', data.DuplicateGroups.length, 'Byte-identical DLLs grouped by SHA-256. Pick a canonical copy and remove the rest.');
    if (data.DuplicateGroups.length === 0) {
        dupSec.appendChild(el('div', { class: 'empty', text: 'No duplicates.' }));
    } else {
        var dupTbl = el('table', null, [
            el('thead', null, [el('tr', null, ['SHA-256', 'Size', 'Count', 'Paths'].map(function (h) { return el('th', { text: h }); }))]),
            el('tbody', null, data.DuplicateGroups.map(function (g) {
                return el('tr', null, [
                    el('td', null, [el('code', { class: 'mono', text: shortHash(g.Sha256) })]),
                    el('td', { text: fmtBytes(g.Size) }),
                    el('td', { text: String(g.Count) }),
                    el('td', null, [el('ul', { class: 'compact' }, g.Paths.map(function (p) { return el('li', null, [el('span', { class: 'mono path', text: p })]); }))])
                ]);
            }))
        ]);
        dupSec.appendChild(dupTbl);
    }
    root.appendChild(dupSec);

    // ----- GUID conflicts -----
    var conflicts = data.GuidConflicts || [];
    var driftCount = conflicts.filter(function (c) { return c.HasDrift; }).length;
    var conflictHeaderClass = driftCount > 0 ? 'bad' : (conflicts.length > 0 ? 'warn' : 'zero');
    var conSec = section('GUID conflicts', conflicts.length, 'Same GUID in DLLs with different SHA-256. DRIFT means the interface or method set also differs across versions.', conflictHeaderClass);

    if (conflicts.length === 0) {
        conSec.appendChild(el('div', { class: 'empty', text: 'No GUID conflicts.' }));
    } else {
        var ctrls = el('div', { class: 'controls' });
        var search = el('input', { type: 'search', placeholder: 'Filter by GUID or name...' });
        var driftOnly = el('input', { type: 'checkbox', id: 'drift-only' });
        var driftLabel = el('label', null, [driftOnly, document.createTextNode(' Drift only')]);
        var coOnly = el('input', { type: 'checkbox', id: 'coclass-only' });
        var coLabel = el('label', null, [coOnly, document.createTextNode(' CoClasses only')]);
        ctrls.appendChild(search);
        ctrls.appendChild(driftLabel);
        ctrls.appendChild(coLabel);
        conSec.appendChild(ctrls);

        var conTbl = el('table');
        var thead = el('thead', null, [el('tr', null, ['', 'Kind', 'Name', 'GUID', 'Versions', 'Occurrences'].map(function (h) { return el('th', { text: h }); }))]);
        conTbl.appendChild(thead);
        var tbody = el('tbody');
        conflicts.forEach(function (c) {
            var badge = c.HasDrift ? el('span', { class: 'badge bad', text: 'drift' }) : el('span', { class: 'badge warn', text: 'dup-guid' });
            var occList = el('ul', { class: 'compact' }, c.Occurrences.map(function (o) {
                var sig = c.Kind === 'coclass' ? ('ifaces=' + o.IfaceCount) : ('methods=' + o.MethodCount);
                return el('li', null, [el('span', { class: 'mono path', text: o.Path + '  [' + shortHash(o.Sha256) + ' ' + sig + ']' })]);
            }));
            var tr = el('tr', null, [
                el('td', null, [badge]),
                el('td', null, [el('span', { class: 'kind-' + c.Kind, text: c.Kind })]),
                el('td', { text: c.Name || '' }),
                el('td', null, [el('code', { class: 'mono guid', text: c.Guid })]),
                el('td', { text: String(c.DistinctVersions) }),
                el('td', null, [occList])
            ]);
            tr.dataset.guid = (c.Guid || '').toLowerCase();
            tr.dataset.name = (c.Name || '').toLowerCase();
            tr.dataset.kind = c.Kind || '';
            tr.dataset.drift = c.HasDrift ? '1' : '0';
            tbody.appendChild(tr);
        });
        conTbl.appendChild(tbody);
        conSec.appendChild(conTbl);

        function applyFilter() {
            var q = search.value.toLowerCase();
            var d = driftOnly.checked;
            var co = coOnly.checked;
            for (var i = 0; i < tbody.rows.length; i++) {
                var r = tbody.rows[i];
                var match = true;
                if (q && r.dataset.guid.indexOf(q) === -1 && r.dataset.name.indexOf(q) === -1) match = false;
                if (d && r.dataset.drift !== '1') match = false;
                if (co && r.dataset.kind !== 'coclass') match = false;
                r.classList.toggle('hidden', !match);
            }
        }
        search.addEventListener('input', applyFilter);
        driftOnly.addEventListener('change', applyFilter);
        coOnly.addEventListener('change', applyFilter);
    }
    root.appendChild(conSec);

    // ----- Registration status -----
    var regStatus = data.RegistrationStatus || [];
    var regSec = section('Registration status', regStatus.length, 'For each conflicted CoClass GUID, where the OS-level registration currently points.');
    if (regStatus.length === 0) {
        regSec.appendChild(el('div', { class: 'empty', text: 'No conflicted CoClasses to report.' }));
    } else {
        var regTbl = el('table', null, [
            el('thead', null, [el('tr', null, ['Status', 'CLSID', 'Name', 'Registered to', 'Hive', 'View'].map(function (h) { return el('th', { text: h }); }))]),
            el('tbody', null, regStatus.map(function (r) {
                var cls = r.State === 'NotRegistered' ? 'warn'
                        : r.State === 'RegisteredOutsideScan' ? 'info'
                        : r.State === 'RegisteredToScanned' ? 'ok' : 'muted';
                return el('tr', null, [
                    el('td', null, [el('span', { class: 'badge ' + cls, text: r.State })]),
                    el('td', null, [el('code', { class: 'mono guid', text: r.Clsid })]),
                    el('td', { text: r.Name || '' }),
                    el('td', null, [el('span', { class: 'mono path', text: r.RegisteredPath || '-' })]),
                    el('td', { text: r.Hive || '' }),
                    el('td', { text: r.View || '' })
                ]);
            }))
        ]);
        regSec.appendChild(regTbl);
    }
    root.appendChild(regSec);

    // ----- All DLLs -----
    var dlls = data.Dlls || [];
    var dllSec = section('All DLLs', dlls.length, 'Full inventory of every PE that was parsed.');
    if (dlls.length === 0) {
        dllSec.appendChild(el('div', { class: 'empty', text: 'No DLLs parsed.' }));
    } else {
        var dllCtrls = el('div', { class: 'controls' });
        var dllSearch = el('input', { type: 'search', placeholder: 'Filter by path or library name...' });
        dllCtrls.appendChild(dllSearch);
        dllSec.appendChild(dllCtrls);

        var dllTbl = el('table');
        dllTbl.appendChild(el('thead', null, [el('tr', null, ['Path', 'Size', 'SHA-256', 'COM', 'TypeLib', 'Entries'].map(function (h) { return el('th', { text: h }); }))]));
        var dbody = el('tbody');
        dlls.forEach(function (d) {
            var comBadge = d.IsComServer ? el('span', { class: 'badge ok', text: 'COM' }) : el('span', { class: 'badge muted', text: '-' });
            var tlb = d.HasTypeLib ? (d.LibName + ' v' + d.LibVersion) : '-';
            var ec = (d.Entries || []).length;
            var tr = el('tr', null, [
                el('td', null, [el('span', { class: 'mono path', text: d.Path })]),
                el('td', { text: fmtBytes(d.Size) }),
                el('td', null, [el('code', { class: 'mono', text: shortHash(d.Sha256) })]),
                el('td', null, [comBadge]),
                el('td', { text: tlb }),
                el('td', { text: String(ec) })
            ]);
            tr.dataset.path = (d.Path || '').toLowerCase();
            tr.dataset.lib = (d.LibName || '').toLowerCase();
            dbody.appendChild(tr);
        });
        dllTbl.appendChild(dbody);
        dllSec.appendChild(dllTbl);

        dllSearch.addEventListener('input', function () {
            var q = dllSearch.value.toLowerCase();
            for (var i = 0; i < dbody.rows.length; i++) {
                var r = dbody.rows[i];
                var match = !q || r.dataset.path.indexOf(q) !== -1 || r.dataset.lib.indexOf(q) !== -1;
                r.classList.toggle('hidden', !match);
            }
        });
    }
    root.appendChild(dllSec);

    function section(title, count, desc, countClass) {
        var sec = el('section');
        var h = el('h2', null, [document.createTextNode(title)]);
        if (count != null) {
            var cls = countClass || (count === 0 ? 'zero' : '');
            h.appendChild(el('span', { class: 'count' + (cls ? ' ' + cls : ''), text: String(count) }));
        }
        sec.appendChild(h);
        if (desc) sec.appendChild(el('div', { class: 'desc', text: desc }));
        return sec;
    }
})();
'@

        # ---- Final HTML ------------------------------------------------
        # Inline HTML escape to avoid taking a dependency on System.Web.
        $enc = {
            param([string]$s)
            if (-not $s) { return '' }
            $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
        }

        $hostEnc   = & $enc $Analysis.HostName
        $scanEnc   = & $enc ([string]$Analysis.ScannedAt)
        $schemaEnc = & $enc ([string]$Analysis.Schema)
        $titleEnc  = & $enc $title

        $html = "<!DOCTYPE html>`r`n<html lang=`"en`">`r`n<head>`r`n" +
                "<meta charset=`"utf-8`">`r`n" +
                "<meta name=`"viewport`" content=`"width=device-width,initial-scale=1`">`r`n" +
                "<title>$titleEnc</title>`r`n" +
                "<style>`r`n$css`r`n</style>`r`n</head>`r`n<body>`r`n" +
                "<header>`r`n" +
                "  <h1>DLL Suite Analysis</h1>`r`n" +
                "  <div class=`"meta`">`r`n" +
                "    <span>Host: $hostEnc</span>`r`n" +
                "    <span>Scanned: $scanEnc</span>`r`n" +
                "    <span>Schema: $schemaEnc</span>`r`n" +
                "  </div>`r`n" +
                "</header>`r`n" +
                "<main id=`"root`"></main>`r`n" +
                "<footer>Generated by SysUtils <code>Invoke-DllSuiteAnalysis</code> + <code>New-DllSuiteReport</code></footer>`r`n" +
                "<script id=`"data`" type=`"application/json`">`r`n$safeJson`r`n</script>`r`n" +
                "<script>window.__SUITE_ANALYSIS__ = JSON.parse(document.getElementById('data').textContent);</script>`r`n" +
                "<script>`r`n$js`r`n</script>`r`n" +
                "</body>`r`n</html>`r`n"

        Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
        Write-Verbose "HTML report written to $OutputPath"
    }
}
