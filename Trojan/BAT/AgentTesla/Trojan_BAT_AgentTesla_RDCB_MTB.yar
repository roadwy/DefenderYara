
rule Trojan_BAT_AgentTesla_RDCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 95 d2 13 16 11 14 11 16 61 13 17 11 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}