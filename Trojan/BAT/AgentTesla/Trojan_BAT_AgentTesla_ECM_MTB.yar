
rule Trojan_BAT_AgentTesla_ECM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ECM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e5 02 06 03 eb 02 e8 02 e9 02 d4 02 0d 03 05 03 01 03 df 02 e7 02 df 02 df 02 e1 02 df 02 e9 02 df 02 05 03 df 02 df 02 e9 02 e0 02 ef 02 df 02 df 02 df 02 f7 02 e2 02 e7 02 ea 02 d6 02 } //01 00 
		$a_01_1 = {69 00 66 00 75 00 5f 00 54 00 } //00 00  ifu_T
	condition:
		any of ($a_*)
 
}