
rule TrojanDownloader_AndroidOS_FireHelper_A{
	meta:
		description = "TrojanDownloader:AndroidOS/FireHelper.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {12 00 21 21 35 10 0c 00 48 01 02 00 df 01 01 37 8d 11 4f 01 02 00 d8 00 00 01 28 f4 } //01 00 
		$a_00_1 = {66 69 72 65 68 65 6c 70 65 72 2e 6a 61 72 } //01 00 
		$a_00_2 = {66 69 72 65 68 65 6c 70 65 72 2e 64 65 78 } //01 00 
		$a_01_3 = {5a 47 46 73 64 6d 6c 72 4c 6e 4e 35 63 33 52 6c 62 53 35 45 5a 58 68 44 62 47 46 7a 63 30 78 76 59 57 52 6c 63 67 3d 3d } //01 00 
		$a_00_4 = {63 6f 2e 6c 2e 6d } //01 00 
		$a_00_5 = {46 49 52 45 59 4d 4e 5f 32 } //00 00 
	condition:
		any of ($a_*)
 
}