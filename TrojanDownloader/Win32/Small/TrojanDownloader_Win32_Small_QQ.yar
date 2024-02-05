
rule TrojanDownloader_Win32_Small_QQ{
	meta:
		description = "TrojanDownloader:Win32/Small.QQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 6c 66 72 65 64 6f 2e 6d 79 70 68 6f 74 6f 73 2e 63 63 2f 73 63 72 69 70 74 73 2f 76 69 65 77 2e 61 73 70 } //04 00 
		$a_01_1 = {7e 44 46 42 41 31 37 2e 74 6d 70 } //03 00 
		$a_01_2 = {25 73 3f 73 69 64 3d 25 30 38 58 25 30 38 58 } //00 00 
	condition:
		any of ($a_*)
 
}