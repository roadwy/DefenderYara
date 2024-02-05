
rule TrojanDownloader_O97M_Donoff_MXIT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXIT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 4e 6c 6d 65 20 3d 20 22 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 6a 64 64 64 73 64 73 64 69 66 64 69 69 6a 69 6a 73 6a 63 6a 6f 73 64 6a 22 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 25 20 5f } //01 00 
		$a_01_2 = {46 69 6c 65 4e 6f 6f 6d 65 20 2b 20 46 69 6c 65 4e 6c 6c 6d 65 2c 20 31 } //01 00 
		$a_01_3 = {46 69 6c 65 4e 6c 6c 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 6c 6d 65 } //01 00 
		$a_01_4 = {46 69 6c 65 4e 6f 6f 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 78 6d 65 } //01 00 
		$a_01_5 = {46 69 6c 65 4e 78 6d 65 20 3d 20 22 6d 73 68 74 61 22 } //00 00 
	condition:
		any of ($a_*)
 
}