
rule Trojan_BAT_AgentTesla_AUO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {02 08 07 6f 90 01 03 0a 13 90 01 01 06 12 90 01 01 28 90 01 03 0a 6f 90 01 03 0a 06 12 90 01 01 28 90 01 03 0a 6f 90 01 03 0a 06 12 90 01 01 28 90 01 03 0a 6f 90 01 03 0a 08 17 d6 0c 08 02 6f 90 01 03 0a 32 90 01 01 07 17 d6 0b 07 02 90 00 } //10
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  1
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}