
rule Trojan_BAT_AgentTesla_SUZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 20 00 14 01 00 5d 07 06 20 00 14 01 00 5d 91 08 06 1f 16 5d 6f 90 01 03 0a 61 07 06 17 58 20 00 14 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d b9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}