
rule Trojan_BAT_AgentTesla_HB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {91 11 05 11 05 07 84 95 11 05 08 84 95 d7 6e 20 90 01 04 6a 5f b7 95 61 86 9c 06 11 09 12 00 28 90 01 04 2d 94 90 00 } //01 00 
		$a_80_1 = {50 72 6f 70 65 72 5f 52 43 34 } //Proper_RC4  01 00 
		$a_80_2 = {45 78 65 63 42 79 74 65 73 } //ExecBytes  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_HB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 8e 69 d6 14 80 90 01 03 04 1d 5f 20 90 01 04 80 90 01 03 04 62 d2 20 00 01 00 00 07 20 90 01 04 80 90 01 03 04 8c 90 01 03 01 80 90 01 03 04 11 05 80 90 01 03 04 14 80 90 01 03 04 14 80 90 01 03 04 5d 61 11 06 20 90 01 04 80 90 01 03 04 80 90 01 03 04 b4 9c 07 17 20 90 01 04 8c 90 01 03 01 80 90 01 03 04 d6 0b 07 11 04 3e 66 ff ff ff 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}