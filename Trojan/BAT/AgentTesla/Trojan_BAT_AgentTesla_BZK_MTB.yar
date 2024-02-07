
rule Trojan_BAT_AgentTesla_BZK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {04 02 50 7e 90 01 03 04 91 7e 90 01 03 04 61 d2 9c 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_4 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //00 00  AssemblyResolve
	condition:
		any of ($a_*)
 
}