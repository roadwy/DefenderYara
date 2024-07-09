
rule TrojanDropper_AndroidOS_SAgent_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 30 23 00 ?? ?? 12 01 21 32 35 21 0c 00 48 02 03 01 df 02 02 ?? 8d 22 4f 02 00 01 d8 01 01 01 28 f4 } //1
		$a_03_1 = {13 00 0b 00 23 01 ?? ?? 26 01 16 00 00 00 12 02 35 02 0c 00 48 03 01 02 60 04 ?? ?? b0 34 67 04 ?? ?? d8 02 02 01 28 f5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}