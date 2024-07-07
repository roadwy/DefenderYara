
rule Trojan_BAT_AgentTesla_AME_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 05 12 05 28 90 01 03 0a 17 da 13 06 16 13 07 2b 21 07 11 04 11 07 6f 90 01 03 0a 13 08 11 08 28 90 01 03 0a 13 09 08 06 11 09 b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d9 90 00 } //10
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_2 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //NewLateBinding  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}