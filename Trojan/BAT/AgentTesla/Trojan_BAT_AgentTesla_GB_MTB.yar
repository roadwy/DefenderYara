
rule Trojan_BAT_AgentTesla_GB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {43 72 69 74 69 63 61 6c 41 74 74 72 69 62 75 74 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CriticalAttribute.Resources.resources
		$a_81_1 = {67 65 74 5f 4d 6f 75 73 65 50 6f 73 69 74 69 6f 6e } //1 get_MousePosition
		$a_81_2 = {72 65 6d 6f 76 65 5f 44 6f 75 62 6c 65 43 6c 69 63 6b } //1 remove_DoubleClick
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_6 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_81_7 = {4d 6b 44 69 72 } //1 MkDir
		$a_81_8 = {4e 69 6d 69 74 7a 44 45 56 } //1 NimitzDEV
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_BAT_AgentTesla_GB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 77 00 79 00 6d 00 61 00 73 00 63 00 65 00 6e 00 73 00 6f 00 72 00 65 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 ://wymascensores.com/
		$a_01_1 = {59 00 6f 00 74 00 74 00 61 00 62 00 69 00 74 00 } //1 Yottabit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}