
rule Trojan_BAT_AgentTesla_NAD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 1a 00 00 06 25 28 ?? 00 00 06 75 ?? 00 00 01 6f ?? 00 00 0a 16 a3 ?? 00 00 01 28 ?? 00 00 06 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 34 31 } //1 WindowsFormsApp41
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 73 66 64 73 66 73 6b 61 68 66 68 66 61 6e 6b 6b 6b 61 73 66 23 } //1 #fsdsfdsfskahfhfankkkasf#
		$a_01_1 = {23 66 61 73 66 64 73 66 66 66 61 66 67 73 64 64 64 64 64 6f 6b 75 69 6a 6f 75 69 6c 70 6f 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #fasfdsfffafgsdddddokuijouilpoddddssaf.dll#
		$a_01_2 = {66 61 73 64 66 64 73 66 66 66 66 66 66 67 73 } //1 fasdfdsffffffgs
		$a_01_3 = {23 67 64 66 73 61 66 66 64 73 66 6c 66 73 61 66 67 66 6c 6c 6c 6c 73 2e 64 6c 6c 23 } //1 #gdfsaffdsflfsafgflllls.dll#
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}