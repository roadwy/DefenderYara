
rule Trojan_Win32_Reghack_A{
	meta:
		description = "Trojan:Win32/Reghack.A,SIGNATURE_TYPE_PEHSTR,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 00 73 65 6c 66 64 65 6c 00 2e 62 61 74 00 64 65 6c 20 00 0d 0a 00 72 6d 64 69 72 20 00 00 20 00 62 61 74 63 68 66 69 6c 65 2e 62 61 74 } //10
		$a_01_1 = {52 45 47 45 44 49 54 2e 45 58 45 20 2f 53 20 22 25 7e 66 30 22 } //10 REGEDIT.EXE /S "%~f0"
		$a_01_2 = {5b 2d 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5d } //1 [-HKEY_CURRENT_USER\Software]
		$a_01_3 = {5b 2d 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5d } //1 [-HKEY_CURRENT_USER]
		$a_01_4 = {5b 2d 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5d } //1 [-HKEY_CLASSES_ROOT]
		$a_01_5 = {5b 2d 48 4b 45 59 5f 55 53 45 52 53 5c 2e 44 45 46 41 55 4c 54 5d } //1 [-HKEY_USERS\.DEFAULT]
		$a_01_6 = {5b 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 43 4f 4e 46 49 47 5c 53 59 53 54 45 4d 5d 39 } //1 [HKEY_CURRENT_CONFIG\SYSTEM]9
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=23
 
}