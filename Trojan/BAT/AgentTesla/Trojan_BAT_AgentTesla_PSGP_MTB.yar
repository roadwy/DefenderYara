
rule Trojan_BAT_AgentTesla_PSGP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 24 3b 02 70 18 18 8d 16 00 00 01 25 16 72 34 3b 02 70 a2 25 17 72 38 3b 02 70 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 24 3b 02 70 18 18 8d 16 00 00 01 25 16 72 3c 3b 02 70 a2 25 17 72 40 3b 02 70 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 24 3b 02 70 18 18 8d 16 00 00 01 25 16 72 48 3b 02 70 a2 25 17 72 4c 3b 02 70 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}