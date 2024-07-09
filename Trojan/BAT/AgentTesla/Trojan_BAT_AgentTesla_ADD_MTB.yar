
rule Trojan_BAT_AgentTesla_ADD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 14 00 04 00 00 "
		
	strings :
		$a_00_0 = {0c 08 0d 16 13 04 11 04 16 fe 01 13 07 11 07 2c 02 2b 35 00 00 09 11 04 9a 13 05 11 05 } //10
		$a_03_1 = {26 11 04 17 d6 13 04 00 11 04 09 8e 69 fe 04 16 fe 01 13 08 11 08 2c 09 07 6f [0-04] 0a 2b 03 00 2b af 06 2a } //10
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_3 = {47 65 74 54 79 70 65 } //GetType  2
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=20
 
}