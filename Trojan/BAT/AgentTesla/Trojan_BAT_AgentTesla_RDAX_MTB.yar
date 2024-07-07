
rule Trojan_BAT_AgentTesla_RDAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 06 6f 5f 00 00 0a 11 04 91 08 11 04 08 8e 69 5d 91 61 d2 6f 5e 00 00 0a 11 04 17 58 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}