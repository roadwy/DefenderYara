
rule TrojanDownloader_O97M_Donoff_MXA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 74 65 63 6e 6f 6c 6f 67 69 61 73 6f 6c 61 72 } //01 00 
		$a_01_1 = {61 63 63 65 73 73 6c 69 6e 6b 73 67 72 6f 75 70 } //01 00 
		$a_01_2 = {70 6f 6e 63 68 6f 6b 68 61 6e 61 2e 63 6f 6d } //01 00 
		$a_01_3 = {61 69 72 64 6f 62 75 72 61 63 6f 2e 63 6f 6d } //01 00 
		$a_01_4 = {62 72 2f 64 73 2f 30 31 30 34 } //01 00 
		$a_01_5 = {4e 45 41 2a } //01 00 
		$a_01_6 = {63 6f 6d 2f 64 73 2f 30 31 30 34 } //00 00 
	condition:
		any of ($a_*)
 
}