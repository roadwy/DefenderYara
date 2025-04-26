
rule TrojanDownloader_Win32_Begseabug_A{
	meta:
		description = "TrojanDownloader:Win32/Begseabug.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 42 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeBebugPrivilege
		$a_03_1 = {63 6f 6d 3a 38 30 38 30 [0-06] 2f 73 63 2e 70 6e 67 } //1
		$a_01_2 = {68 2d af 9c 4e } //1
		$a_01_3 = {53 59 53 54 45 4d 33 32 5c 73 79 73 74 65 6d 2e 65 78 65 } //1 SYSTEM32\system.exe
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Begseabug_A_2{
	meta:
		description = "TrojanDownloader:Win32/Begseabug.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 74 08 00 00 8b 45 c4 53 33 db 56 3b c3 57 be 1f ab 01 01 74 ?? be 1f ab 01 01 b9 81 00 00 00 } //5
		$a_00_1 = {8a 04 1a 88 45 ff 8a 45 ff c0 c0 03 88 45 ff 8a 45 ff 32 44 0d c8 41 83 f9 10 88 04 1a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5) >=10
 
}