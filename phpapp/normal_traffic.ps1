$pages = @(
    "http://localhost:8080/php/app.php",
    "http://localhost:8080/php/app.php?page=home",
    "http://localhost:8080/php/app.php?page=search&q=laptop",
    "http://localhost:8080/php/app.php?page=search&q=mouse",
    "http://localhost:8080/php/app.php?page=profile&id=1",
    "http://localhost:8080/php/app.php?page=profile&id=2",
    "http://localhost:8080/php/app.php?page=profile&id=3",
    "http://localhost:8080/",
    "http://localhost:8080/index.html"
)

for ($i=1; $i -le 5000; $i++) {
    $url = $pages[(Get-Random -Maximum $pages.Length)]
    try { iwr -Uri $url -UseBasicParsing | Out-Null } catch {}
    if ($i % 500 -eq 0) { Write-Host "Normal: $i/5000" }
}
Write-Host "Done."