
rule Trojan_BAT_AgentTesla_GB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 69 74 69 63 61 6c 41 74 74 72 69 62 75 74 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  CriticalAttribute.Resources.resources
		$a_81_1 = {67 65 74 5f 4d 6f 75 73 65 50 6f 73 69 74 69 6f 6e } //01 00  get_MousePosition
		$a_81_2 = {72 65 6d 6f 76 65 5f 44 6f 75 62 6c 65 43 6c 69 63 6b } //01 00  remove_DoubleClick
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_6 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_81_7 = {4d 6b 44 69 72 } //01 00  MkDir
		$a_81_8 = {4e 69 6d 69 74 7a 44 45 56 } //00 00  NimitzDEV
	condition:
		any of ($a_*)
 
}