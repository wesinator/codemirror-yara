/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

CodeMirror.defineSimpleMode("yara", {
  // The start state contains the rules that are initially used
  start: [
    // The regex matches the token, the token property contains the type
    {regex: /"(?:[^\\]|\\.)*?(?:"|$)/, token: "string"},
    // You can match multiple tokens at once. Note that the captured
    // groups must span the whole string in this case
    {regex: /(rule)(\s+)([a-zA-Z_][\w$]*)/,
     token: ["keyword", null, "variable-2"]},
    // Rules are matched in the order in which they appear, so there is
    // no ambiguity between this one and the one above
    {regex: /(?:all|and|any|ascii|at|condition|contains|entrypoint|filesize|for|fullword|global|import|in|include|int8|int16|int32|int8be|int16be|int32be|matches|meta|nocase|not|or|of|private|strings|them|uint8|uint16|uint32|uint8be|uint16be|uint32be|wide|xor)\b/,
     token: "keyword"},
    {regex: /true|false/, token: "atom"},
    {regex: /0x[a-f\d]+|(?:\.\d+|\d+\.?\d*)/i,
     token: "number"},
    {regex: /(?<![\w\.])([a-fA-F\d?]{2})+(?![\w\.])/,
     token: "number"},
    {regex: /\/\/.*/, token: "comment"},
    // A next property will cause the mode to move to a different state
    {regex: /\/\*/, token: "comment", next: "comment"},
    {regex: /[-+\/*=<>:]+/, token: "operator"},
    // indent and dedent properties guide autoindentation
    {regex: /\{/, indent: true},
    {regex: /\}/, dedent: true},
    {regex: /\$\w*/, token: "variable"}
  ],
  // The multi-line comment state.
  comment: [
    {regex: /.*?\*\//, token: "comment", next: "start"},
    {regex: /.*/, token: "comment"}
  ],
  // The meta property contains global information about the mode. It
  // can contain properties like lineComment, which are supported by
  // all modes, and also directives like dontIndentStates, which are
  // specific to simple modes.
  meta: {
    dontIndentStates: ["comment"],
    lineComment: "//"
  }
});
