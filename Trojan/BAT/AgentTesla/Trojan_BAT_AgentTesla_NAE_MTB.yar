
rule Trojan_BAT_AgentTesla_NAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 0d 00 00 06 13 02 38 90 01 01 00 00 00 28 90 01 01 00 00 0a 11 00 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 01 20 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {50 75 61 66 6f 77 72 } //00 00  Puafowr
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 36 00 00 0a 72 90 01 02 00 70 6f 90 01 02 00 0a fe 90 01 02 00 fe 90 01 02 00 6f 90 01 02 00 0a d4 8d 90 01 02 00 01 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 20 90 01 02 00 00 fe 90 01 02 00 8e 69 6f 90 01 02 00 0a 26 14 fe 90 01 02 00 73 90 01 02 00 0a fe 90 01 02 00 fe 90 01 02 00 73 90 01 02 00 0a fe 90 01 02 00 fe 90 01 02 00 20 90 01 02 00 00 73 90 01 02 00 0a fe 90 01 02 00 90 00 } //01 00 
		$a_01_1 = {75 6e 70 61 63 6b 6d 65 65 } //00 00  unpackmee
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_1 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_3 = {00 49 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_4 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00  䤀彟彟彟彟I
		$a_01_5 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_6 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00  䤀彟彟彟彟彟I
		$a_01_7 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_8 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //00 00  GetExportedTypes
	condition:
		any of ($a_*)
 
}