
rule Trojan_BAT_AgentTesla_COP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.COP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 1f 7a fe 02 16 fe 01 2b 01 16 0d 09 2c 1f 00 08 1f 6d fe 02 13 04 11 04 2c 09 00 08 1f 0d 59 0c 00 2b 07 00 08 1f 0d 58 0c 00 00 2b 33 08 1f 41 32 0a 08 1f 5a fe 02 16 fe 01 2b 01 16 13 05 11 05 2c 1d 00 08 1f 4d fe 02 13 06 11 06 2c 09 00 08 1f 0d 59 0c 00 2b 07 00 08 1f 0d 58 0c } //1
		$a_01_1 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 4d 00 65 00 74 00 65 00 72 00 } //1 Resource_Meter
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}