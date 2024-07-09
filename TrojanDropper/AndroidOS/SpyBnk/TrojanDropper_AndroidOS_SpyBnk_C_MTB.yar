
rule TrojanDropper_AndroidOS_SpyBnk_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SpyBnk.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 01 00 10 23 11 ?? ?? 21 12 71 20 ?? ?? 29 00 0a 02 12 03 6e 40 ?? ?? 18 23 0a 02 12 f4 32 42 16 00 39 02 03 00 28 12 b1 29 12 04 35 24 0b 00 48 05 01 04 b7 a5 8d 55 4f 05 01 04 d8 04 04 01 28 f6 6e 40 ?? ?? 10 23 28 e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}