
rule Trojan_BAT_AgentTesla_EXW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0e 04 0b 07 17 2e 06 07 18 2e 0a 2b 2d 02 03 5d 0c 08 0a 2b 27 } //1
		$a_01_1 = {4d 00 63 00 7a 00 6a 00 66 00 6b 00 6a 00 4f 00 41 00 44 00 4a 00 6f 00 66 00 51 00 4a 00 46 00 4c 00 4f 00 44 00 4a 00 43 00 4c 00 58 00 4b 00 } //1 MczjfkjOADJofQJFLODJCLXK
		$a_01_2 = {43 00 20 00 6b 00 73 00 64 00 6a 00 67 00 66 00 64 00 73 00 6c 00 6f 00 67 00 70 00 6f 00 6a 00 67 00 69 00 6a 00 64 00 73 00 69 00 61 00 66 00 } //1 C ksdjgfdslogpojgijdsiaf
		$a_81_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}