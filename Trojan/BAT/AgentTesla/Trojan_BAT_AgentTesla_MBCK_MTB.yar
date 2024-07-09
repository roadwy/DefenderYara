
rule Trojan_BAT_AgentTesla_MBCK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 c1 16 00 70 0b 16 13 05 2b 2b 00 07 06 72 f3 16 00 70 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 74 ?? 00 00 01 28 ?? 00 00 0a 0b 00 11 05 17 58 13 05 11 05 1f 34 fe 02 16 fe 01 13 06 11 06 2d c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBCK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 73 64 23 00 23 61 61 2e 64 6c 6c 23 00 23 67 61 61 2e 64 6c 6c 23 00 23 64 61 } //1
		$a_01_1 = {23 68 64 66 73 61 66 61 61 61 61 64 61 64 73 61 64 66 66 66 77 74 77 66 66 66 66 66 66 66 67 73 73 73 73 73 64 66 2e 64 6c 6c 23 } //1 #hdfsafaaaadadsadfffwtwfffffffgsssssdf.dll#
		$a_01_2 = {23 64 73 68 73 73 74 61 64 61 61 61 64 77 73 73 73 73 73 67 2e 64 6c 6c 23 } //1 #dshsstadaaadwsssssg.dll#
		$a_01_3 = {66 73 61 73 73 67 64 73 61 64 66 61 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 61 64 } //1 fsassgdsadfassssssssssssssssssad
		$a_01_4 = {23 61 61 2e 64 6c 6c 23 } //1 #aa.dll#
		$a_01_5 = {23 66 61 73 64 66 67 73 66 73 64 2e 64 6c 6c 23 } //1 #fasdfgsfsd.dll#
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}