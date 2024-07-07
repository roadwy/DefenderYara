
rule Trojan_BAT_AgentTesla_EXN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 1f 16 5d 6f 90 01 03 0a 61 13 01 90 00 } //1
		$a_03_1 = {02 03 17 58 7e 90 01 03 04 5d 91 13 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}