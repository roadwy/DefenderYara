
rule Trojan_BAT_AgentTesla_PTEZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 43 00 00 01 25 16 72 d8 0c 00 70 28 90 01 01 00 00 0a d2 9c 25 17 17 28 90 01 01 00 00 0a 16 91 9c 25 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}