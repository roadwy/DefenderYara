
rule Trojan_BAT_Reline_MR_MTB{
	meta:
		description = "Trojan:BAT/Reline.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 11 00 "
		
	strings :
		$a_02_0 = {fe 0c 01 00 fe 90 02 03 6f 90 02 04 fe 90 02 03 6f 90 02 04 28 90 02 04 28 90 02 04 fe 90 02 03 fe 90 02 03 6f 90 02 04 fe 90 02 03 6f 90 02 04 dd 90 00 } //01 00 
		$a_81_1 = {4e 61 72 69 76 69 61 2e 53 65 6c 65 63 74 69 6f 6e 52 61 6e 67 65 43 6f 6e 76 65 72 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Narivia.SelectionRangeConverter.resources
		$a_81_2 = {24 32 39 66 61 64 37 39 33 2d 35 36 61 37 2d 34 38 30 34 2d 62 36 63 65 2d 30 32 61 66 38 62 31 66 35 65 64 62 } //01 00  $29fad793-56a7-4804-b6ce-02af8b1f5edb
		$a_81_3 = {4e 61 72 69 76 69 61 43 6c 61 73 73 } //01 00  NariviaClass
		$a_81_4 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_5 = {43 6f 70 79 54 6f } //01 00  CopyTo
		$a_81_6 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //01 00  UnaryOperation
		$a_81_7 = {42 69 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //01 00  BinaryOperation
		$a_81_8 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //00 00  GetManifestResourceStream
	condition:
		any of ($a_*)
 
}