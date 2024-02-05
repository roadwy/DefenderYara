
rule Trojan_BAT_AgentTesla_BAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {95 33 56 11 4f 11 2d 2c 07 16 11 17 13 17 2b 01 17 17 59 11 4a 20 1e 10 00 00 95 5f 11 4a 20 94 13 00 00 95 61 58 13 4f } //05 00 
		$a_01_1 = {17 2b 01 16 58 6a 11 4a 20 61 07 00 00 95 6e 31 03 16 2b 01 17 17 59 11 4a 20 d4 07 00 00 95 5f 11 4a 20 71 0b 00 00 95 61 58 13 4f 38 db 13 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BAS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 04 02 28 90 01 03 06 6f 90 01 03 0a 6f 90 01 03 0a 09 11 04 6f 90 01 03 0a 6f 90 01 03 0a 13 05 11 05 17 8d 90 01 03 01 25 16 02 28 90 01 03 06 a2 6f 90 00 } //01 00 
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 64 6c 6c } //01 00 
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_81_3 = {47 65 74 54 79 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}