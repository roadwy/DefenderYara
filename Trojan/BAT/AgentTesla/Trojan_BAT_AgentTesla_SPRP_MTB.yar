
rule Trojan_BAT_AgentTesla_SPRP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 02 07 11 05 28 90 01 03 06 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d d9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}