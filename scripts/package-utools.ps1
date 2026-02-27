param(
  [string]$OutputDir = "dist",
  [string]$Author = "",
  [string]$SourceUrl = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Blacklist mode: copy everything except excluded files/dirs.
$blacklistDirs = @(
  ".git",
  ".utools-package",
  "dist",
  "docs",
  "scripts"
)
$blacklistFiles = @(
  ".gitignore"
)

function Get-GitConfigValue {
  param([string]$Key)

  try {
    $value = git config --get $Key 2>$null
    if ($LASTEXITCODE -eq 0 -and $value) {
      return ($value | Select-Object -First 1).Trim()
    }
  } catch {
    # Ignore and fallback later.
  }

  return ""
}

function Convert-GitRemoteToWebUrl {
  param([string]$RemoteUrl)

  if ([string]::IsNullOrWhiteSpace($RemoteUrl)) {
    return ""
  }

  $url = $RemoteUrl.Trim()
  if ($url -match '^https?://') {
    return ($url -replace '\.git$')
  }

  if ($url -match '^git@([^:]+):(.+)$') {
    $gitHost = $Matches[1]
    $path = ($Matches[2] -replace '\.git$')
    return "https://$gitHost/$path"
  }

  if ($url -match '^ssh://git@([^/]+)/(.+)$') {
    $gitHost = $Matches[1]
    $path = ($Matches[2] -replace '\.git$')
    return "https://$gitHost/$path"
  }

  return $url
}

function Get-WatermarkHeader {
  param(
    [string]$RelativePath,
    [string]$Body
  )

  $ext = [System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
  switch ($ext) {
    ".html" { return "<!--`r`n$Body`r`n-->`r`n`n" }
    ".css" { return "/*`r`n$Body`r`n*/`r`n`n" }
    ".js" { return "/*`r`n$Body`r`n*/`r`n`n" }
    default { return "" }
  }
}

function Set-FileTextWithPrefixUtf8NoBom {
  param(
    [string]$Path,
    [string]$Prefix
  )

  if (-not (Test-Path $Path)) {
    throw "Watermark target file not found: $Path"
  }

  $existing = [System.IO.File]::ReadAllText($Path)
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Prefix + $existing, $utf8NoBom)
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot $OutputDir
$templatePath = Join-Path $PSScriptRoot "watermark.template.txt"
$versionPath = Join-Path $projectRoot "VERSION"

if (-not (Test-Path $templatePath)) {
  throw "Watermark template not found: $templatePath"
}
if (-not (Test-Path $versionPath)) {
  throw "VERSION file not found: $versionPath"
}

$version = (Get-Content -Path $versionPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($version)) {
  throw "VERSION file is empty: $versionPath"
}

if ([string]::IsNullOrWhiteSpace($Author)) {
  $Author = Get-GitConfigValue -Key "user.name"
}
if ([string]::IsNullOrWhiteSpace($Author)) {
  $Author = "Unknown Author"
}

if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
  $remoteOrigin = Get-GitConfigValue -Key "remote.origin.url"
  $SourceUrl = Convert-GitRemoteToWebUrl -RemoteUrl $remoteOrigin
}
if ([string]::IsNullOrWhiteSpace($SourceUrl)) {
  $SourceUrl = "N/A"
}

$buildTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
$templateRaw = Get-Content -Path $templatePath -Raw
$watermarkBody = $templateRaw
$watermarkBody = $watermarkBody.Replace("{{AUTHOR}}", $Author)
$watermarkBody = $watermarkBody.Replace("{{SOURCE_URL}}", $SourceUrl)
$watermarkBody = $watermarkBody.Replace("{{VERSION}}", $version)
$watermarkBody = $watermarkBody.Replace("{{BUILD_TIME_UTC}}", $buildTimeUtc)

if (Test-Path $outputPath) {
  Remove-Item -Path $outputPath -Recurse -Force
}
New-Item -ItemType Directory -Path $outputPath | Out-Null

$outputDirHead = ($OutputDir -split '[\\/]' | Where-Object { $_ }) | Select-Object -First 1
if ($outputDirHead -and -not ($blacklistDirs -contains $outputDirHead)) {
  $blacklistDirs += $outputDirHead
}

$sourceFiles = Get-ChildItem -Path $projectRoot -Recurse -File -Force | Where-Object {
  $relativePath = $_.FullName.Substring($projectRoot.Length).TrimStart('\')
  $segments = $relativePath -split '[\\/]'

  foreach ($segment in $segments) {
    if ($blacklistDirs -contains $segment) {
      return $false
    }
  }

  if ($blacklistFiles -contains $relativePath) {
    return $false
  }

  return $true
}

foreach ($sourceFile in $sourceFiles) {
  $relativePath = $sourceFile.FullName.Substring($projectRoot.Length).TrimStart('\')
  $sourcePath = $sourceFile.FullName
  $targetPath = Join-Path $outputPath $relativePath
  $targetDir = Split-Path -Parent $targetPath
  if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
  }

  Copy-Item -Path $sourcePath -Destination $targetPath -Force
}

$watermarkTargets = @(
  "index.html",
  "index.css",
  "index.js",
  "preload.js"
)

foreach ($relativePath in $watermarkTargets) {
  $targetPath = Join-Path $outputPath $relativePath
  if (-not (Test-Path $targetPath)) {
    continue
  }

  $header = Get-WatermarkHeader -RelativePath $relativePath -Body $watermarkBody
  if (-not [string]::IsNullOrWhiteSpace($header)) {
    Set-FileTextWithPrefixUtf8NoBom -Path $targetPath -Prefix $header
  }
}

$copied = Get-ChildItem -Path $outputPath -Recurse -File
$totalBytes = ($copied | Measure-Object -Property Length -Sum).Sum

Write-Host "Package directory created: $outputPath"
Write-Host ("File count: {0}, Total size: {1} bytes" -f $copied.Count, $totalBytes)
Write-Host ("Watermark version: {0}" -f $version)
Write-Host ("Watermark author: {0}" -f $Author)
Write-Host ("Watermark source: {0}" -f $SourceUrl)
Write-Host "Copied files:"
foreach ($file in $copied) {
  $relative = $file.FullName.Substring($outputPath.Length).TrimStart('\')
  Write-Host ("- {0}" -f $relative)
}
