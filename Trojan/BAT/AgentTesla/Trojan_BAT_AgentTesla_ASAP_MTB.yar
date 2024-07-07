
rule Trojan_BAT_AgentTesla_ASAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 07 11 04 72 90 01 01 3e 00 70 28 90 01 01 03 00 06 d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d d4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}