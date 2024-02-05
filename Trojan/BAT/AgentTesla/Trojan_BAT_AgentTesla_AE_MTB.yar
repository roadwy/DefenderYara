
rule Trojan_BAT_AgentTesla_AE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 04 08 9a 13 07 11 07 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 90 00 } //0a 00 
		$a_02_1 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 90 00 } //01 00 
		$a_80_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  01 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  01 00 
		$a_80_4 = {47 65 74 54 79 70 65 } //GetType  01 00 
		$a_80_5 = {47 65 74 53 65 74 4d 65 74 68 6f 64 } //GetSetMethod  01 00 
		$a_80_6 = {47 65 74 50 72 6f 70 65 72 74 69 65 73 } //GetProperties  01 00 
		$a_80_7 = {49 6e 76 6f 6b 65 } //Invoke  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {20 6c 10 00 00 95 e0 95 7e 0e 01 00 04 20 cf 04 00 00 95 61 7e 0e 01 00 04 20 10 07 00 00 95 2e 03 17 2b 01 16 58 7e 52 00 00 04 } //04 00 
		$a_01_1 = {1f 40 95 2c 03 16 2b 01 17 7e 88 00 00 04 18 20 01 01 01 01 13 2c 9a 20 41 06 00 00 95 5a 7e 88 00 00 04 18 9a 20 5e 08 00 00 95 58 61 80 34 00 00 04 } //04 00 
		$a_01_2 = {37 03 16 2b 01 17 17 59 7e 62 00 00 04 20 0d 0c 00 00 95 5f 7e 62 00 00 04 20 94 00 00 00 95 61 58 81 0b 00 00 01 } //04 00 
		$a_01_3 = {1a 9a 08 0b 20 1f 12 00 00 95 5f 7e 38 00 00 04 1a 9a 20 ca 0d 00 00 95 61 58 81 09 00 00 01 38 54 01 00 00 7e 40 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}