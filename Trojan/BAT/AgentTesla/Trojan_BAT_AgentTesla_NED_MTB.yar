
rule Trojan_BAT_AgentTesla_NED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 29 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 0f 11 0f 28 ?? ?? ?? 0a 13 10 08 11 04 11 10 d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 11 11 11 2d cc 07 17 58 0b 00 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NED_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6c 6c 6f 72 20 50 61 6c 6c 65 74 65 73 } //1 Collor Palletes
		$a_01_1 = {76 34 2e 30 2e 33 30 33 31 39 } //1 v4.0.30319
		$a_01_2 = {72 65 6d 6f 76 65 5f 44 6f 57 6f 72 6b } //1 remove_DoWork
		$a_01_3 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 50 41 44 50 41 } //1 b77a5c561934e089PADPA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}