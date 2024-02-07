
rule Trojan_BAT_AgentTesla_BTN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {9e 02 02 7b 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 94 02 7b 90 01 03 04 02 7b 90 01 03 04 94 58 20 00 01 00 00 5d 94 7d 90 01 03 04 02 7b 90 01 03 04 02 7b 90 01 03 04 03 02 7b 90 01 03 04 91 02 7b 90 01 03 04 61 d2 9c 02 02 7b 90 01 03 04 17 58 7d 90 01 03 04 02 7b 90 01 03 04 03 8e 69 90 00 } //01 00 
		$a_81_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_2 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //01 00  AssemblyResolve
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}