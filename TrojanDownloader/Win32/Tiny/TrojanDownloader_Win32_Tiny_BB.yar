
rule TrojanDownloader_Win32_Tiny_BB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.BB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 2e 00 74 00 68 00 65 00 63 00 2e 00 63 00 6e 00 2f 00 77 00 67 00 33 00 36 00 39 00 2f 00 6d 00 6d 00 2e 00 65 00 78 00 65 00 } //05 00 
		$a_01_1 = {63 00 3a 00 5c 00 63 00 2e 00 65 00 78 00 65 00 } //05 00 
		$a_01_2 = {57 69 6e 45 78 65 63 } //05 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}