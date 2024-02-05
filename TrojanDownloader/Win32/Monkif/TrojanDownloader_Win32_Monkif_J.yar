
rule TrojanDownloader_Win32_Monkif_J{
	meta:
		description = "TrojanDownloader:Win32/Monkif.J,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {75 72 6f 6d 6f 6e 2e 64 6c 6c } //0a 00 
		$a_10_1 = {31 36 33 38 30 31 } //0a 00 
		$a_00_2 = {25 75 7c 00 48 54 54 50 2f 31 2e 30 00 } //0a 00 
		$a_00_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00 
		$a_01_4 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49 } //01 00 
		$a_01_5 = {c6 45 ef 43 c6 45 f0 6f c6 45 f1 6e c6 45 f2 6e c6 45 f3 65 c6 45 f4 63 c6 45 f5 74 c6 45 f6 65 c6 45 f7 64 c6 45 f8 5a c6 45 f9 74 c6 45 fa 61 c6 45 fb 74 c6 45 fc 65 } //00 00 
	condition:
		any of ($a_*)
 
}