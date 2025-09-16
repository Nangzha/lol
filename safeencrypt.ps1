<#
.SYNOPSIS
  Recursively encrypt files under a source folder with specific extensions,
  and write encrypted copies into a separate output folder using AES-CBC with PBKDF2 (SHA256).

.NOTES
  - Output format: [16-byte Salt][16-byte IV][Ciphertext...]
  - Originals are NOT deleted.
  - Test in a VM/sandbox first.
#>

param(
  [Parameter(Mandatory=$true)] [string]$SourcePath,
  [Parameter(Mandatory=$true)] [string]$Password,

  # Root output folder for encrypted copies
  [string]$OutputRoot = "D:\Encrypted",

  # PBKDF2 iterations
  [int]$Iterations = 200000,

  # Dry run mode -> don't write any encrypted files
  [switch]$DryRun,

  # Maximum file size to encrypt (default 10 GB)
  [int64]$MaxFileSizeBytes = 10GB,

  # List of extensions to INCLUDE (case-insensitive). Example: @('.txt','.pdf','.png')
  # Use '*' to match all files (subject to other guards).
  [string[]]$IncludeExtensions = @('.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.docx', '.xlsx', '.pptx', '.csv', '.md'),

  # List of extensions to EXCLUDE even if included above
  [string[]]$ExcludeExtensions = @('.exe', '.dll', '.sys', '.bat', '.cmd', '.msi')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validation
if (-not (Test-Path -LiteralPath $SourcePath -PathType Container)) {
  throw "Source path not found or not a directory: $SourcePath"
}

# Normalize
$SourceFull = (Resolve-Path -LiteralPath $SourcePath).Path.TrimEnd('\')
if (-not (Test-Path -LiteralPath $OutputRoot)) {
  New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}
$OutputRootFull = (Resolve-Path -LiteralPath $OutputRoot).Path.TrimEnd('\')

$Log = [System.Collections.Generic.List[string]]::new()

function Get-RelativePath {
  param($base, $target)
  $b = $base.TrimEnd('\') + '\'
  $t = $target
  if ($t.StartsWith($b, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $t.Substring($b.Length)
  }
  return $t
}

function Normalize-Ext {
  param([string]$ext)
  if ([string]::IsNullOrWhiteSpace($ext)) { return '' }
  if ($ext.StartsWith('.')) { return $ext.ToLower() }
  return ('.' + $ext.ToLower())
}

# Normalize include/exclude lists
$IncludeNormalized = @()
foreach ($e in $IncludeExtensions) { $IncludeNormalized += Normalize-Ext -ext $e }
$ExcludeNormalized = @()
foreach ($e in $ExcludeExtensions) { $ExcludeNormalized += Normalize-Ext -ext $e }

function Should-ProcessFile {
  param([IO.FileInfo]$File)

  # zero-length
  if ($File.Length -eq 0) { return $false, "zero-length" }

  # size
  if ($File.Length -gt $MaxFileSizeBytes) { return $false, "too-large" }

  $ext = $File.Extension.ToLower()

  # explicit exclude
  if ($ExcludeNormalized -contains $ext) { return $false, "excluded-ext" }

  # wildcard include
  if ($IncludeNormalized -contains '*' -or $IncludeNormalized -contains '.*') { return $true, "include-all" }

  # include match
  if ($IncludeNormalized -contains $ext) { return $true, "include-match" }

  return $false, "not-in-include-list"
}

function Encrypt-FileToPath {
  param(
    [string]$InputFile,
    [string]$OutFile,
    [string]$Password,
    [int]$Iterations
  )

  $outDir = Split-Path -Path $OutFile -Parent
  if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

  # Salt
  $Salt = New-Object byte[] 16
  [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Salt)

  # AES setup
  $AES = New-Object System.Security.Cryptography.AesManaged
  $AES.Mode    = [System.Security.Cryptography.CipherMode]::CBC
  $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

  # PBKDF2 -> key
  $PBKDF2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    [Text.Encoding]::UTF8.GetBytes($Password),
    $Salt,
    $Iterations,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256
  )
  $AES.Key = $PBKDF2.GetBytes(32)
  $AES.GenerateIV()

  $inStream  = [IO.File]::OpenRead($InputFile)
  $outStream = [IO.File]::Create($OutFile)
  try {
    $outStream.Write($Salt, 0, $Salt.Length)
    $outStream.Write($AES.IV, 0, $AES.IV.Length)

    $encryptor = $AES.CreateEncryptor()
    $crypto = New-Object System.Security.Cryptography.CryptoStream($outStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    try {
      $inStream.CopyTo($crypto)
    } finally {
      $crypto.FlushFinalBlock()
      $crypto.Dispose()
      $encryptor.Dispose()
    }
  } finally {
    $inStream.Dispose()
    $outStream.Dispose()
    $AES.Dispose()
  }
}

# Gather files
Write-Host "Scanning files under: $SourceFull"
$files = Get-ChildItem -Path $SourceFull -Recurse -File -ErrorAction SilentlyContinue

if ($files.Count -eq 0) { Write-Host "No files found."; return }

foreach ($f in $files) {
  try {
    $should, $reason = Should-ProcessFile -File $f
    if (-not $should) {
      $Log.Add("SKIP [$reason] $($f.FullName)")
      continue
    }

    $rel = Get-RelativePath -base $SourceFull -target $f.FullName
    $outPath = Join-Path -Path $OutputRootFull -ChildPath $rel
    $outFile = "$outPath.lock"

    Write-Host "Encrypting -> $outFile"
    if ($DryRun) {
      $Log.Add("DRYRUN would encrypt $($f.FullName) -> $outFile")
      continue
    }

    Encrypt-FileToPath -InputFile $f.FullName -OutFile $outFile -Password $Password -Iterations $Iterations
    $Log.Add("OK $($f.FullName) -> $outFile")
  } catch {
    $Log.Add("ERR $($f.FullName) : $($_.Exception.Message)")
  }
}

# Write log
$logFile = Join-Path -Path $OutputRootFull -ChildPath ("encrypt-log-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
$Log | Out-File -FilePath $logFile -Encoding UTF8

Write-Host "Done. Log: $logFile"
