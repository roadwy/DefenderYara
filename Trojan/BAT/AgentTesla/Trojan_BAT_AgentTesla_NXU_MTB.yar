
rule Trojan_BAT_AgentTesla_NXU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 00 00 1b 6b 00 63 00 6a 00 69 } //1
		$a_81_1 = {6b 63 6a 69 6a 69 77 6f 65 66 75 77 39 } //1 kcjijiwoefuw9
		$a_81_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //1 GetManifestResourceNames
		$a_81_3 = {76 64 66 67 65 } //1 vdfge
		$a_81_4 = {58 58 52 58 65 58 66 58 6c 58 65 58 63 58 58 58 74 58 58 58 69 58 58 6f 58 58 6e 58 } //1 XXRXeXfXlXeXcXXXtXXXiXXoXXnX
		$a_81_5 = {58 58 41 58 73 58 73 58 65 58 6d 58 62 58 6c 58 58 58 79 58 58 } //1 XXAXsXsXeXmXbXlXXXyXX
		$a_81_6 = {58 58 53 58 58 79 58 73 58 74 58 58 58 65 58 58 6d 58 } //1 XXSXXyXsXtXXXeXXmX
		$a_81_7 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}