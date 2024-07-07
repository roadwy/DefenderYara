
rule Trojan_BAT_AgentTesla_NYT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {78 4d 78 65 78 74 78 68 78 6f 78 64 78 30 78 } //1 xMxextxhxoxdx0x
		$a_01_1 = {2e 00 72 00 65 00 73 00 6f 00 00 07 75 00 72 00 63 00 00 05 65 00 73 00 00 1f 78 00 4d 00 78 00 65 } //1
		$a_01_2 = {4d 00 63 00 7a 00 6a 00 66 00 6b 00 6a 00 4f 00 41 00 44 00 4a 00 6f 00 66 00 51 00 4a 00 46 00 4c 00 4f 00 44 00 4a 00 43 00 4c 00 58 00 4b 00 } //1 MczjfkjOADJofQJFLODJCLXK
		$a_01_3 = {43 00 20 00 6b 00 73 00 64 00 6a 00 67 00 66 00 64 00 73 00 6c 00 6f 00 67 00 70 00 6f 00 6a 00 67 00 69 00 6a 00 64 00 73 00 69 00 61 00 66 00 } //1 C ksdjgfdslogpojgijdsiaf
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}