
rule TrojanDropper_AndroidOS_SAgent_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 0c 00 6e 10 ?? 00 ?? 00 0c ?? 71 20 ?? 00 ?? 00 54 ?? ?? 00 72 20 ?? 00 ?? 00 } //2
		$a_01_1 = {35 32 12 00 34 40 03 00 01 10 48 05 07 02 48 06 08 00 b7 65 8d 55 4f 05 07 02 d8 02 02 01 d8 00 00 01 28 ef } //1
		$a_01_2 = {35 20 12 00 34 31 03 00 12 01 48 04 06 00 48 05 07 01 b7 54 8d 44 4f 04 06 00 d8 00 00 01 d8 01 01 01 28 ef } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}