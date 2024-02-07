
rule Trojan_Win32_Danabot_K{
	meta:
		description = "Trojan:Win32/Danabot.K,SIGNATURE_TYPE_PEHSTR,06 00 06 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 2d 43 6f 6d 70 75 74 65 72 52 65 73 74 6f 72 65 20 22 43 3a 5c 22 } //01 00  Disable-ComputerRestore "C:\"
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 } //01 00  powershell.exe -ExecutionPolicy Bypass
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 54 65 61 6d 56 69 65 77 65 72 2e 65 78 65 } //01 00  taskkill /F /IM TeamViewer.exe
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 6a 75 73 63 68 65 64 2e 65 78 65 } //01 00  taskkill /F /IM jusched.exe
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 6d 69 6b 72 6f 63 6c 69 65 6e 74 77 73 65 72 76 69 63 65 } //01 00  net stop mikroclientwservice
		$a_01_5 = {6e 65 74 20 73 74 6f 70 20 4d 53 53 51 4c 24 4d 49 4b 52 4f } //01 00  net stop MSSQL$MIKRO
		$a_01_6 = {6e 65 74 20 73 74 6f 70 20 66 6f 78 69 74 72 65 61 64 65 72 73 65 72 76 69 63 65 } //01 00  net stop foxitreaderservice
		$a_01_7 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //01 00  Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
		$a_01_8 = {41 64 76 61 6e 63 65 64 22 20 2f 76 20 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //02 00  Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
		$a_01_9 = {48 6f 77 54 6f 42 61 63 6b 46 69 6c 65 73 2e 74 78 74 } //02 00  HowToBackFiles.txt
		$a_01_10 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //02 00  @protonmail.com
		$a_01_11 = {45 6e 63 72 79 70 74 65 72 } //00 00  Encrypter
	condition:
		any of ($a_*)
 
}