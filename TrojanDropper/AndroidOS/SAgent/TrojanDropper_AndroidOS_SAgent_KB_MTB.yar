
rule TrojanDropper_AndroidOS_SAgent_KB_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.KB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 03 19 00 92 04 01 03 d8 05 04 02 6e 30 90 01 02 46 05 0c 04 13 05 10 00 71 20 90 01 02 54 00 0c 04 6e 10 90 01 02 04 00 0a 04 4f 04 02 03 d8 03 03 01 28 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}