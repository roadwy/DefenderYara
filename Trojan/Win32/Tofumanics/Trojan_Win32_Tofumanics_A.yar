
rule Trojan_Win32_Tofumanics_A{
	meta:
		description = "Trojan:Win32/Tofumanics.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 55 6e 69 43 61 6d 20 53 6f 66 74 57 61 72 65 } //1 Common Files\UniCam SoftWare
		$a_00_1 = {72 65 67 20 61 64 64 20 22 68 6b 65 79 5f 6c 6f 63 61 6c 5f 6d 61 63 68 69 6e 65 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 6e 74 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 77 69 6e 6c 6f 67 6f 6e 20 22 20 2f 76 20 73 68 65 6c 6c 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 20 22 45 78 70 6c 6f 72 65 72 2e 65 78 65 2c } //1 reg add "hkey_local_machine\software\microsoft\windows nt\currentversion\winlogon " /v shell /t reg_sz /d "Explorer.exe,
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 57 65 62 4d 6f 6e 65 79 5c 70 61 74 68 } //1 Software\WebMoney\path
		$a_03_3 = {72 65 66 75 73 65 2e 74 78 74 00 90 02 0a 74 69 6d 69 6e 67 2e 74 78 74 00 90 00 } //1
		$a_03_4 = {4d 41 4c 57 41 52 45 00 90 02 10 45 53 53 45 4e 54 49 41 4c 53 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}