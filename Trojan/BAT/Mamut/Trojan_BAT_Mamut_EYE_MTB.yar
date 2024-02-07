
rule Trojan_BAT_Mamut_EYE_MTB{
	meta:
		description = "Trojan:BAT/Mamut.EYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 68 36 6a 32 69 6a 67 72 33 32 69 34 33 32 35 68 34 75 35 6b 6a 68 32 6a 69 33 32 33 34 69 36 33 35 74 6f } //01 00  5h6j2ijgr32i4325h4u5kjh2ji3234i635to
		$a_01_1 = {24 31 63 34 66 32 35 65 38 2d 30 34 38 37 2d 34 32 65 64 2d 61 63 37 65 2d 37 62 36 30 35 61 32 37 64 33 33 61 } //01 00  $1c4f25e8-0487-42ed-ac7e-7b605a27d33a
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_4 = {51 75 61 6e 74 75 6d 42 75 69 6c 64 65 72 } //01 00  QuantumBuilder
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}