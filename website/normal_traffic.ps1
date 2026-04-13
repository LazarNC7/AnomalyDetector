$existente = @('/', '/index.html')
$erori = @('/about')
for ($i=1; $i -le 500; $i++) {
  if ((Get-Random -Maximum 10) -lt 9) {
    $page = $existente[(Get-Random -Maximum 2)]
  } else {
    $page = $erori[(Get-Random -Maximum 3)]
  }
  try {
    iwr -Uri "http://localhost:8080$page" -UseBasicParsing | Out-Null
  } catch {}
  if ($i % 100 -eq 0) { Write-Host "Normal traffic: $i/500" }
}
Write-Host "Normal traffic done."