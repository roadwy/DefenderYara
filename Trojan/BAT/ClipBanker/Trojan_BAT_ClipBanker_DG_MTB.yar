
rule Trojan_BAT_ClipBanker_DG_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4b 00 4b 00 0b 00 00 32 00 "
		
	strings :
		$a_81_0 = {66 61 69 73 69 67 71 77 64 } //32 00  faisigqwd
		$a_81_1 = {64 61 73 69 6f 77 66 } //32 00  dasiowf
		$a_81_2 = {6f 61 73 64 6f 70 6f 61 73 64 } //32 00  oasdopoasd
		$a_81_3 = {6b 67 73 6f 64 66 64 73 6b 7a } //14 00  kgsodfdskz
		$a_81_4 = {44 69 73 63 6f 72 64 20 4c 69 6e 6b } //01 00  Discord Link
		$a_81_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_8 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_9 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_10 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}