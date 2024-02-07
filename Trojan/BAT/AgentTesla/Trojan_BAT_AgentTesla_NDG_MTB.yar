
rule Trojan_BAT_AgentTesla_NDG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {df 02 ea 02 05 03 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 ef 02 df 02 df 02 df 02 df 02 df 02 df } //01 00 
		$a_01_1 = {03 ec 02 e7 02 00 03 05 03 e0 02 f2 02 eb 02 ce 02 06 03 f4 02 e5 02 06 03 0e 03 01 03 17 03 e0 } //01 00 
		$a_01_2 = {02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 ed 02 df 02 df 02 df 02 07 03 e3 02 ea 02 df 02 ef 02 05 03 df 02 df 02 e2 02 0d 03 df 02 df 02 df } //01 00 
		$a_01_3 = {02 ce 02 13 03 15 03 df 02 df 02 f5 02 f1 02 14 03 11 03 e1 02 f6 02 f3 02 e8 02 df 02 df 02 df 02 e0 02 00 03 } //01 00 
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_5 = {49 5f 30 30 30 30 30 30 33 } //01 00  I_0000003
		$a_01_6 = {49 5f 30 30 30 30 30 30 38 } //01 00  I_0000008
		$a_01_7 = {49 5f 30 32 30 33 } //01 00  I_0203
		$a_01_8 = {49 5f 30 39 33 31 32 33 31 32 33 } //01 00  I_093123123
		$a_81_9 = {42 75 2d 6e 69 2d 2d 66 75 5f 54 2d 2d 65 78 2d 2d 74 42 6f 2d 2d 2d 78 } //00 00  Bu-ni--fu_T--ex--tBo---x
	condition:
		any of ($a_*)
 
}