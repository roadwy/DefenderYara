
rule TrojanDropper_AndroidOS_SAgent_J_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgent.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {21 12 34 20 08 00 22 00 90 02 04 70 20 90 02 04 10 00 11 00 49 02 01 00 df 03 02 ff d5 33 ed 6c d5 22 12 93 b6 32 8e 22 8e 22 50 02 01 00 90 02 16 21 13 35 32 15 00 d8 00 90 02 04 d8 00 00 01 d8 00 90 02 04 49 02 01 00 df 03 02 ff b5 03 df 04 00 ff b5 42 b6 32 8e 22 8e 22 50 02 01 00 90 00 } //01 00 
		$a_03_1 = {21 12 34 20 08 00 22 90 02 04 00 70 20 90 02 04 10 00 11 00 49 02 01 00 d5 23 12 93 df 02 02 ff d5 22 ed 6c b6 32 8e 22 8e 22 8e 22 50 02 01 00 90 02 16 21 13 35 32 16 00 d8 00 90 02 04 d8 00 00 01 d8 00 90 02 04 49 02 01 00 df 03 00 ff b5 23 df 02 02 ff b5 02 b6 32 8e 22 8e 22 8e 22 50 02 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}