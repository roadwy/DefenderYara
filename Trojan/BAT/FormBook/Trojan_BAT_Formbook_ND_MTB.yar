
rule Trojan_BAT_Formbook_ND_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9f 00 00 00 13 00 00 00 4c 00 00 00 b0 00 00 00 5e 00 00 00 2b 01 00 00 34 01 00 00 01 } //01 00 
		$a_01_1 = {61 34 35 39 2d 31 33 63 33 30 64 33 30 61 61 30 37 } //01 00  a459-13c30d30aa07
		$a_01_2 = {53 51 4c 41 70 70 4c 6f 67 69 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  SQLAppLogin.Resources.resource
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}