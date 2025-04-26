
rule Trojan_BAT_AgentTesla_ATK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ATK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 03 33 06 07 04 fe 01 2b 01 16 0c 08 2c 03 00 2b 01 00 07 17 58 0b 07 02 7b 0f 00 00 04 6f 38 00 00 06 fe 04 0d 09 2d d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}