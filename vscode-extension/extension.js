const vscode = require('vscode');
const { execSync, spawn } = require('child_process');
const path = require('path');

let diagnosticCollection;
let outputChannel;

function activate(context) {
  outputChannel = vscode.window.createOutputChannel('PledgeGuard');
  context.subscriptions.push(outputChannel);

  diagnosticCollection = vscode.languages.createDiagnosticCollection('pledgeguard');
  context.subscriptions.push(diagnosticCollection);

  context.subscriptions.push(
    vscode.commands.registerCommand('pledgeguard.scan', () => scanWorkspace()),
    vscode.commands.registerCommand('pledgeguard.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('pledgeguard.init', () => initConfig()),
  );

  if (vscode.workspace.getConfiguration('pledgeguard').get('enableOnSave')) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(doc => scanDocument(doc))
    );
  }
}

function getBinary() {
  const configPath = vscode.workspace.getConfiguration('pledgeguard').get('binaryPath');
  if (configPath) return configPath;
  return null;
}

function buildCommand(args) {
  const binary = getBinary();
  if (binary) {
    return [binary, args];
  }
  return ['npx', ['pledgeguard@latest', ...args]];
}

function scanWorkspace() {
  const wsPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!wsPath) {
    vscode.window.showWarningMessage('PledgeGuard: No workspace open.');
    return;
  }
  outputChannel.show();
  outputChannel.appendLine('PledgeGuard: Scanning workspace...');

  const minSeverity = vscode.workspace.getConfiguration('pledgeguard').get('minSeverity');
  const [cmd, args] = buildCommand(['scan', wsPath, '--format', 'json', '--min-severity', minSeverity]);

  try {
    const output = execSync([cmd, ...args].join(' '), { encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 });
    const findings = JSON.parse(output);
    displayFindings(findings);
  } catch (e) {
    outputChannel.appendLine(`PledgeGuard: Error — ${e.message}`);
  }
}

function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  scanDocument(editor.document);
}

function scanDocument(doc) {
  if (doc.uri.scheme !== 'file') return;
  const filePath = doc.uri.fsPath;

  const minSeverity = vscode.workspace.getConfiguration('pledgeguard').get('minSeverity');
  const [cmd, args] = buildCommand(['scan', filePath, '--format', 'json', '--min-severity', minSeverity]);

  try {
    const output = execSync([cmd, ...args].join(' '), { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
    const findings = JSON.parse(output);
    displayFindingsForFile(doc.uri, findings);
  } catch (e) {
  }
}

function displayFindings(findings) {
  const diagnostics = {};
  for (const f of findings) {
    const uri = vscode.Uri.file(f.path);
    if (!diagnostics[uri.fsPath]) diagnostics[uri.fsPath] = [];
    const range = new vscode.Range(
      Math.max(0, f.line - 1), Math.max(0, f.column - 1),
      Math.max(0, f.line - 1), Math.max(0, f.column + 50),
    );
    const severity = f.severity === 'Critical' ? vscode.DiagnosticSeverity.Error
      : f.severity === 'High' ? vscode.DiagnosticSeverity.Error
      : f.severity === 'Medium' ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;
    const diag = new vscode.Diagnostic(range, `[${f.severity}] ${f.rule_id}: ${f.description}`, severity);
    diag.source = 'pledgeguard';
    diagnostics[uri.fsPath].push(diag);
  }

  diagnosticCollection.clear();
  for (const [fsPath, diags] of Object.entries(diagnostics)) {
    const uri = vscode.Uri.file(fsPath);
    diagnosticCollection.set(uri, diags);
  }

  outputChannel.appendLine(`PledgeGuard: ${findings.length} finding(s).`);
}

function displayFindingsForFile(uri, findings) {
  const diags = findings.map(f => {
    const range = new vscode.Range(
      Math.max(0, f.line - 1), Math.max(0, f.column - 1),
      Math.max(0, f.line - 1), Math.max(0, f.column + 50),
    );
    const severity = f.severity === 'Critical' || f.severity === 'High'
      ? vscode.DiagnosticSeverity.Error
      : f.severity === 'Medium'
      ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;
    const diag = new vscode.Diagnostic(range, `[${f.severity}] ${f.rule_id}: ${f.description}`, severity);
    diag.source = 'pledgeguard';
    return diag;
  });
  diagnosticCollection.set(uri, diags);
}

function initConfig() {
  const wsPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!wsPath) return;
  const [cmd, args] = buildCommand(['init', wsPath]);
  try {
    execSync([cmd, ...args].join(' '), { encoding: 'utf8' });
    vscode.window.showInformationMessage('PledgeGuard: Config created (.pledgeguard.toml)');
  } catch (e) {
    vscode.window.showErrorMessage(`PledgeGuard: ${e.message}`);
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
