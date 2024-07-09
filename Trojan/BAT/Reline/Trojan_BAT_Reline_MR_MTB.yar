
rule Trojan_BAT_Reline_MR_MTB{
	meta:
		description = "Trojan:BAT/Reline.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_02_0 = {fe 0c 01 00 fe [0-03] 6f [0-04] fe [0-03] 6f [0-04] 28 [0-04] 28 [0-04] fe [0-03] fe [0-03] 6f [0-04] fe [0-03] 6f [0-04] dd } //17
		$a_81_1 = {4e 61 72 69 76 69 61 2e 53 65 6c 65 63 74 69 6f 6e 52 61 6e 67 65 43 6f 6e 76 65 72 74 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 Narivia.SelectionRangeConverter.resources
		$a_81_2 = {24 32 39 66 61 64 37 39 33 2d 35 36 61 37 2d 34 38 30 34 2d 62 36 63 65 2d 30 32 61 66 38 62 31 66 35 65 64 62 } //1 $29fad793-56a7-4804-b6ce-02af8b1f5edb
		$a_81_3 = {4e 61 72 69 76 69 61 43 6c 61 73 73 } //1 NariviaClass
		$a_81_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_5 = {43 6f 70 79 54 6f } //1 CopyTo
		$a_81_6 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 UnaryOperation
		$a_81_7 = {42 69 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 BinaryOperation
		$a_81_8 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
	condition:
		((#a_02_0  & 1)*17+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=17
 
}