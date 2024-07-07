
rule Trojan_BAT_AgentTesla_BDR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {02 02 8e 69 17 da 91 1f 70 61 0c 20 02 00 00 00 90 01 05 02 8e 69 17 d6 17 da 17 d6 8d 90 01 03 01 0d 02 8e 69 17 da 13 04 11 04 13 05 16 13 06 90 01 05 09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}