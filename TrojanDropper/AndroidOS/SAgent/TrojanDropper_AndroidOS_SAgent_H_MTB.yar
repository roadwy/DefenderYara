
rule TrojanDropper_AndroidOS_SAgent_H_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 1a 00 35 41 1e 00 dc 04 01 03 44 05 03 04 e2 05 05 08 44 06 03 04 e0 06 06 18 b6 65 b0 05 b7 15 4b 05 03 04 [0-10] b6 50 44 04 03 04 b7 40 d8 01 01 01 4b 00 02 01 28 e1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}