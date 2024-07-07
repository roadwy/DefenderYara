
rule Trojan_BAT_AgentTesla_BAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 14 72 4a 4b 02 70 18 8d 90 01 01 00 00 01 25 16 72 5a 4b 02 70 a2 25 17 72 5e 4b 02 70 a2 14 14 14 28 90 02 03 0a 14 72 4a 4b 02 70 18 8d 90 01 01 00 00 01 25 16 72 66 4b 02 70 a2 25 17 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}