
rule Trojan_BAT_AgentTesla_PSVF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 91 02 00 0a 73 bc 04 00 06 28 ?? 04 00 06 75 7c 00 00 1b 6f ?? 02 00 0a 0b 07 14 28 ?? 02 00 0a 2c 11 07 20 92 37 4d a6 28 ?? 05 00 06 6f ?? 02 00 0a 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}