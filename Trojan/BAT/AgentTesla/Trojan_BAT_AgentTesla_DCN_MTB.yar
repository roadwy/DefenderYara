
rule Trojan_BAT_AgentTesla_DCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 93 0c 08 1f 61 32 0a 08 1f 7a fe 02 16 fe 01 2b 01 16 0d 09 2c 19 08 1f 6d fe 02 13 04 11 04 2c 07 08 1f 0d 59 0c 2b 05 08 1f 0d 58 0c 2b 2d 08 } //1
		$a_01_1 = {1f 41 32 0a 08 1f 5a fe 02 16 fe 01 2b 01 16 13 05 11 05 2c 17 08 1f 4d fe 02 13 06 11 06 2c 07 08 1f 0d 59 0c 2b 05 08 1f 0d 58 0c 06 07 08 d1 9d 07 17 58 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}