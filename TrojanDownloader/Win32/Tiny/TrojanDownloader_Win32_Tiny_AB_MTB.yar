
rule TrojanDownloader_Win32_Tiny_AB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 69 6e 73 74 61 6c 6c 2e 69 6e 66 } //01 00 
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 35 00 34 00 2e 00 32 00 31 00 31 00 2e 00 31 00 34 00 2e 00 39 00 31 00 2f 00 33 00 36 00 30 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}