
rule Trojan_BAT_Formbook_EU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {53 74 61 67 67 65 72 69 6e 67 49 73 6f 6d 65 74 72 69 63 4d 61 70 2e 52 65 73 6f 75 72 63 65 73 } //14 00  StaggeringIsometricMap.Resources
		$a_81_1 = {53 69 73 74 65 6d 61 56 65 6e 74 61 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //14 00  SistemaVentas.Resources.resources
		$a_81_2 = {46 54 50 4c 69 73 74 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  FTPLister.My.Resources
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {53 75 79 65 6f 6e 20 53 74 61 67 67 65 72 69 6e 67 20 49 73 6f 6d 65 74 72 69 63 20 4d 61 70 } //01 00  Suyeon Staggering Isometric Map
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {53 69 73 74 65 6d 61 20 64 65 20 56 65 6e 74 61 73 20 4d 55 } //01 00  Sistema de Ventas MU
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {44 65 76 6f 6c 65 70 6f 72 73 40 67 6d 61 6c 2e 63 6f 6d } //01 00  Devolepors@gmal.com
		$a_81_9 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}