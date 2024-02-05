
rule TrojanDownloader_Win64_Bingom_PA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Bingom.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 63 6f 64 65 62 69 6e 64 2e 65 78 65 } //01 00 
		$a_03_1 = {6e 74 66 6c 78 2d 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 2e 78 79 7a 2f 90 02 15 2f 65 78 65 2f 73 65 74 68 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}