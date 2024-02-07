
rule Trojan_BAT_ClipBanker_L_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 48 00 6e 00 35 00 36 00 79 00 75 00 62 00 6f 00 64 00 64 00 33 00 71 00 76 00 6d 00 4d 00 38 00 33 00 4b 00 4b 00 66 00 6f 00 5a 00 55 00 63 00 46 00 75 00 72 00 31 00 47 00 4e 00 38 00 43 00 72 } //01 00 
		$a_01_1 = {35 66 34 63 37 62 37 34 2d 33 64 65 39 2d 34 35 38 38 2d 61 36 65 31 2d 34 36 61 38 39 35 38 35 33 62 63 36 } //01 00  5f4c7b74-3de9-4588-a6e1-46a895853bc6
		$a_01_2 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_81_3 = {43 68 72 6f 6d 65 55 70 64 61 74 65 2e 65 78 65 } //01 00  ChromeUpdate.exe
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}