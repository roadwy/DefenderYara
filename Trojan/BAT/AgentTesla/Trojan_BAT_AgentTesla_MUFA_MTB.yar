
rule Trojan_BAT_AgentTesla_MUFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 6f 90 01 03 0a 5d 6f 90 01 03 0a 28 90 01 03 06 07 91 73 90 01 03 0a 0c 28 90 01 03 06 07 08 6f 90 01 03 0a 08 6f 90 01 03 0a 61 28 90 01 03 0a 9c 00 07 17 58 0b 07 28 90 01 03 06 8e 69 fe 04 0d 09 2d b8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}