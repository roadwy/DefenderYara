
rule TrojanDownloader_AndroidOS_Gapac_B_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Gapac.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 6e 64 65 6c 69 6f 6e 6d 6f 62 2e 63 6f 6d 2f 73 73 70 } //01 00 
		$a_01_1 = {73 2e 6f 6a 69 65 67 61 6d 65 2e 63 6f 6d } //01 00 
		$a_01_2 = {53 74 65 61 72 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_3 = {6f 70 65 6e 61 70 70 2e 6a 64 6d 6f 62 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}