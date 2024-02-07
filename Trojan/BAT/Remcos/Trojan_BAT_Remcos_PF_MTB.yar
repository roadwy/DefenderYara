
rule Trojan_BAT_Remcos_PF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 09 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 62 32 64 39 30 33 30 30 2d 37 31 39 35 2d 34 38 37 32 2d 62 65 33 39 2d 62 66 38 38 35 31 62 38 31 34 62 33 } //14 00  $b2d90300-7195-4872-be39-bf8851b814b3
		$a_81_1 = {24 33 33 34 66 33 62 65 39 2d 30 31 33 31 2d 34 61 34 35 2d 38 36 36 61 2d 31 36 32 62 65 39 65 32 36 66 63 62 } //01 00  $334f3be9-0131-4a45-866a-162be9e26fcb
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {53 74 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Stub.g.resources
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}