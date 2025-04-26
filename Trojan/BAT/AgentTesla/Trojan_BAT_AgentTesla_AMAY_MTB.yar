
rule Trojan_BAT_AgentTesla_AMAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 11 01 8e 69 5d 02 11 01 11 03 11 01 8e 69 5d 91 11 02 11 03 11 02 6f ?? 01 00 0a 5d 28 ?? 02 00 06 61 28 ?? 01 00 0a 11 01 11 03 17 58 11 01 8e 69 5d 91 28 ?? 01 00 0a 59 20 00 01 00 00 58 28 ?? 02 00 06 28 ?? 01 00 0a 9c 20 ?? 00 00 00 38 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}