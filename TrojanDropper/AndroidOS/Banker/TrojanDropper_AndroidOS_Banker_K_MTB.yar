
rule TrojanDropper_AndroidOS_Banker_K_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 00 00 20 23 05 ?? ?? 01 10 6e 20 ?? ?? 5b 00 0a 06 3a 06 27 00 ?? ?? ?? ?? 01 12 34 70 06 00 6e 40 ?? ?? 5c 61 28 f2 dc 08 00 08 db 09 08 04 dc 0a 00 04 39 08 05 00 71 20 ?? ?? 34 00 44 08 03 09 da 09 0a 08 b9 98 8d 88 48 09 05 02 b7 98 8d 88 4f 08 05 02 d8 00 00 01 d8 02 02 01 28 df 0e 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}