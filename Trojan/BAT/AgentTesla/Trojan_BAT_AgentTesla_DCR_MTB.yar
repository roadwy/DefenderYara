
rule Trojan_BAT_AgentTesla_DCR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 1f 6d fe 02 13 04 11 04 2c 03 16 2b 03 17 2b 00 2d 09 00 08 1f 0d 59 0c 00 2b 07 00 08 1f 0d 58 0c 00 00 2b 43 08 1f 41 32 0a 08 1f 5a fe 02 16 fe 01 2b 01 } //1
		$a_01_1 = {16 13 05 11 05 2c 03 16 2b 03 17 2b 00 2d 25 00 08 1f 4d fe 02 13 06 11 06 2c 03 16 2b 03 17 2b 00 2d 09 00 08 1f 0d 59 0c 00 2b 07 00 08 1f 0d 58 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}