
rule Trojan_BAT_AgentTesla_GAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 21 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a d2 13 05 08 11 05 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}