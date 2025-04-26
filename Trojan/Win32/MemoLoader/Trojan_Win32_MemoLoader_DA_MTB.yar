
rule Trojan_Win32_MemoLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/MemoLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
		$a_81_1 = {4e 65 77 2d 4f 62 6a 65 63 74 20 2d 43 6f 6d 4f 62 6a 65 63 74 20 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 } //1 New-Object -ComObject "WScript.Shell"
		$a_81_2 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 22 24 65 6e 76 3a 41 50 50 44 41 54 41 } //1 CreateShortcut("$env:APPDATA
		$a_81_3 = {48 4b 43 55 3a 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_4 = {50 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 65 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 55 6e 72 65 73 74 72 69 63 74 65 64 20 2d 46 69 6c 65 } //1 Powershell.exe -executionPolicy Unrestricted -File
		$a_03_5 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 73 00 63 00 72 00 69 00 70 00 74 00 5c 00 [0-0f] 2e 00 70 00 73 00 31 00 } //1
		$a_03_6 = {43 3a 5c 54 65 6d 70 73 63 72 69 70 74 5c [0-0f] 2e 70 73 31 } //1
		$a_81_7 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 73 20 35 } //1 Start-Sleep -s 5
		$a_81_8 = {52 65 73 74 61 72 74 2d 43 6f 6d 70 75 74 65 72 } //1 Restart-Computer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}