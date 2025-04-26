
rule Trojan_BAT_AgentTesla_PTJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 7e 16 00 00 04 fe 06 36 00 00 06 73 15 00 00 0a 25 80 17 00 00 04 28 ?? 00 00 2b 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}