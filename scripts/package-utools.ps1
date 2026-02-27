param(
  [string]$OutputDir = ".utools-package",
  [switch]$IncludeReadme
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot $OutputDir

# Copy only whitelisted files to avoid shipping .git and dev files.
$whitelist = @(
  "plugin.json",
  "index.html",
  "index.css",
  "index.js",
  "preload.js",
  "logo.png",
  "vendor/jsQR.js"
)

if ($IncludeReadme) {
  $whitelist += "README.md"
}

if (Test-Path $outputPath) {
  Remove-Item -Path $outputPath -Recurse -Force
}
New-Item -ItemType Directory -Path $outputPath | Out-Null

foreach ($relativePath in $whitelist) {
  $sourcePath = Join-Path $projectRoot $relativePath
  if (-not (Test-Path $sourcePath)) {
    throw "Whitelisted file not found: $relativePath"
  }

  $targetPath = Join-Path $outputPath $relativePath
  $targetDir = Split-Path -Parent $targetPath
  if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
  }

  Copy-Item -Path $sourcePath -Destination $targetPath -Force
}

$copied = Get-ChildItem -Path $outputPath -Recurse -File
$totalBytes = ($copied | Measure-Object -Property Length -Sum).Sum

Write-Host "Package directory created: $outputPath"
Write-Host ("File count: {0}, Total size: {1} bytes" -f $copied.Count, $totalBytes)
Write-Host "Copied files:"
foreach ($file in $copied) {
  $relative = $file.FullName.Substring($outputPath.Length).TrimStart('\')
  Write-Host ("- {0}" -f $relative)
}
