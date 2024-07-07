
rule Trojan_BAT_AgentTesla_ABKR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 08 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a a2 25 17 1f 10 8c 90 01 03 01 a2 6f 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 00 11 04 90 0a 53 00 09 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 20 90 01 03 00 14 14 18 8d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}