
rule TrojanDropper_O97M_Bartallex{
	meta:
		description = "TrojanDropper:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 6f 72 22 20 26 20 22 64 2e 22 20 26 20 22 41 70 70 6c 69 63 61 74 69 6f 22 } //01 00  CreateObject("Wor" & "d." & "Applicatio"
		$a_01_1 = {3d 20 22 2e 72 74 66 22 } //01 00  = ".rtf"
		$a_01_2 = {3d 20 22 54 22 20 26 20 22 45 4d 22 } //00 00  = "T" & "EM"
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_O97M_Bartallex_2{
	meta:
		description = "TrojanDropper:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 26 20 22 57 22 20 26 20 22 22 20 26 20 22 6f 72 22 20 26 20 22 64 2e 22 20 26 20 22 41 70 70 6c 69 63 61 74 69 6f } //01 00  CreateObject("" & "W" & "" & "or" & "d." & "Applicatio
		$a_01_1 = {26 20 22 2e 72 74 66 22 } //01 00  & ".rtf"
		$a_01_2 = {26 20 22 54 22 20 26 20 22 45 4d 22 } //00 00  & "T" & "EM"
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_O97M_Bartallex_3{
	meta:
		description = "TrojanDropper:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 61 73 65 28 22 77 69 4e 33 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 64 6f 72 50 5f 32 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 20 74 63 75 22 29 } //01 00  Lcase("wiN3") & StrReverse("dorP_2") & StrReverse(" tcu")
		$a_01_1 = {69 76 6f 72 79 20 26 20 22 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //00 00  ivory & ".\root\cimv2")
	condition:
		any of ($a_*)
 
}