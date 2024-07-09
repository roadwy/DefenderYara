
rule TrojanDropper_AndroidOS_SpyBnk_H_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SpyBnk.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 00 08 23 77 ?? ?? 21 78 71 20 ?? ?? 83 00 0a 08 6e 40 ?? ?? 72 85 0a 08 12 f9 32 98 16 00 39 08 03 00 28 12 b1 83 12 09 35 89 0b 00 48 0a 07 09 b7 4a 8d aa 4f 0a 07 09 d8 09 09 01 28 f6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}