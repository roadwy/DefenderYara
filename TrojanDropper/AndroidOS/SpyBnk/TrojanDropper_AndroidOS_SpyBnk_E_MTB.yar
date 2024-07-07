
rule TrojanDropper_AndroidOS_SpyBnk_E_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SpyBnk.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 01 00 10 23 12 2d 00 71 20 90 01 02 1a 00 0a 03 12 04 6e 40 90 01 02 29 34 0a 03 12 f5 32 53 16 00 39 03 03 00 28 12 b1 3a 12 05 35 35 0b 00 48 06 02 05 b7 b6 8d 66 4f 06 02 05 d8 05 05 01 28 f6 6e 40 90 01 02 20 34 28 e1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}