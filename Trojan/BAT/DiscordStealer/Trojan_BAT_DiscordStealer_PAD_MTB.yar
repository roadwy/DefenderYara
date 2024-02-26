
rule Trojan_BAT_DiscordStealer_PAD_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 53 79 73 74 65 6d 2e 64 6c 6c } //taskkill /im System.dll  01 00 
		$a_80_1 = {52 45 47 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //REG add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f  01 00 
		$a_80_2 = {52 45 47 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 43 4d 44 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //REG add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f  01 00 
		$a_80_3 = {52 65 56 61 4c 61 54 69 6f 4e 20 4b 65 79 6c 6f 67 67 65 72 20 4c 6f 67 } //ReVaLaTioN Keylogger Log  01 00 
		$a_80_4 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 49 4d 56 55 5c 75 73 65 72 6e 61 6d 65 5c } //HKEY_CURRENT_USER\Software\IMVU\username\  01 00 
		$a_80_5 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 49 4d 56 55 5c 70 61 73 73 77 6f 72 64 5c } //HKEY_CURRENT_USER\Software\IMVU\password\  01 00 
		$a_01_6 = {55 70 6c 6f 61 64 46 69 6c 65 } //01 00  UploadFile
		$a_80_7 = {5b 4c 4f 47 5d 2e 74 78 74 } //[LOG].txt  01 00 
		$a_80_8 = {43 3a 5c 4b 46 4a 44 39 34 37 44 48 43 2e 65 78 65 } //C:\KFJD947DHC.exe  00 00 
	condition:
		any of ($a_*)
 
}