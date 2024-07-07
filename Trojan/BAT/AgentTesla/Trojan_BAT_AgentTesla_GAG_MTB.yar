
rule Trojan_BAT_AgentTesla_GAG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 20 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 05 08 11 05 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d1 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}