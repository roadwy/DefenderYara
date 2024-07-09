
rule TrojanDropper_AndroidOS_SAgent_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 70 23 02 ?? ?? 62 00 ?? ?? 21 03 01 10 21 74 35 40 11 00 48 04 07 00 62 05 ?? ?? 94 06 00 03 48 05 05 06 b7 54 8d 44 4f 04 02 00 d8 00 00 01 28 ef 62 00 ?? ?? 21 00 21 73 35 31 11 00 48 03 02 01 62 04 ?? ?? 94 05 01 00 48 04 04 05 b7 43 8d 33 4f 03 02 01 d8 01 01 01 28 ef } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}