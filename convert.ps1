param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("BASE64", "BASE64E", "BASE64D", "MD5", "SHA1", "SHA256", "SHA384", "SHA512", IgnoreCase = $true)]
  [string]$type,
  
  [Parameter(Mandatory = $true)]
  [string]$value
)

switch ($type) {
  "BASE64" {
    $result = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($value))
  }
  "BASE64E" {
    $result = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($value))
  }
  "BASE64D" {
    $result = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($value))
  }
  "MD5" {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = [System.BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))).Replace("-", "").ToLower()
    $result = $hash
  }
  "SHA1" {
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))).Replace("-", "").ToLower()
    $result = $hash
  }
  "SHA256" {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))).Replace("-", "").ToLower()
    $result = $hash
  }
  "SHA384" {
    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    $hash = [System.BitConverter]::ToString($sha384.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))).Replace("-", "").ToLower()
    $result = $hash
  }
  "SHA512" {
    $sha512 = [System.Security.Cryptography.SHA512]::Create()
    $hash = [System.BitConverter]::ToString($sha512.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value))).Replace("-", "").ToLower()
    $result = $hash
  }
  default {
    Write-Host "Invalid type: $type"
    exit
  }
}

Write-Host "Convertion result: $result"
Set-Clipboard -Value $result
Write-Host "Result copied to clipboard"