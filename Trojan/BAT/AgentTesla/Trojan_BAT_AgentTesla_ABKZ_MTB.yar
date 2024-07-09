
rule Trojan_BAT_AgentTesla_ABKZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 08 08 11 08 9a 1f 10 28 ?? 00 00 0a d2 6f ?? 00 00 0a 00 11 08 17 58 13 08 11 08 08 8e 69 fe 04 13 09 11 09 2d d8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}