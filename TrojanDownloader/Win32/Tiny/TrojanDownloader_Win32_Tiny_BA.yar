
rule TrojanDownloader_Win32_Tiny_BA{
	meta:
		description = "TrojanDownloader:Win32/Tiny.BA,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 65 6d 62 65 72 73 2e 6c 79 63 6f 73 2e 63 6f 2e 75 6b 2f 71 61 6c 62 68 61 6d 61 64 2f 73 65 74 75 70 2e 65 78 65 20 } //05 00 
		$a_01_1 = {43 3a 5c 64 6f 73 2e 70 69 66 2e 2e 2e 2e 2e 2e } //05 00 
		$a_01_2 = {57 69 6e 45 78 65 63 } //05 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}