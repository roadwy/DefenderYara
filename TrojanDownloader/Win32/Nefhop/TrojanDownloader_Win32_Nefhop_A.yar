
rule TrojanDownloader_Win32_Nefhop_A{
	meta:
		description = "TrojanDownloader:Win32/Nefhop.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {32 33 34 35 68 61 6f 7a 69 70 5f 6b 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {6a 69 66 65 6e 5f 32 33 34 35 } //01 00 
		$a_01_2 = {43 3a 5c 31 69 6e 69 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 32 33 34 35 2e 63 6f 6d } //01 00 
		$a_01_4 = {44 3a 5c 64 72 65 61 6d 5c 77 69 6e 31 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}