
rule Trojan_BAT_AgentTesla_AMAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 8e 69 5d 13 07 11 04 08 6f 90 01 01 00 00 0a 5d 13 08 07 11 07 91 13 09 08 11 08 6f 90 01 01 00 00 0a 13 0a 02 07 11 04 28 90 01 01 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 90 01 01 00 00 06 13 0c 07 11 07 02 11 0c 28 90 01 01 00 00 06 9c 11 04 17 59 13 04 00 11 04 16 fe 04 16 fe 01 13 0d 11 0d 2d a2 90 00 } //5
		$a_01_1 = {03 8e 69 0a 03 04 17 58 06 5d 91 0b 2b 00 07 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}