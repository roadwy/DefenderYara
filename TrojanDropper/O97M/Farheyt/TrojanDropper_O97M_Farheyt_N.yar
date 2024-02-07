
rule TrojanDropper_O97M_Farheyt_N{
	meta:
		description = "TrojanDropper:O97M/Farheyt.N,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {26 20 22 74 6d 70 22 90 02 0f 90 12 0f 00 20 3d 20 90 02 0f 26 90 02 05 72 74 66 22 90 02 2f 2b 20 90 1b 01 90 00 } //01 00 
		$a_01_1 = {2b 20 22 66 68 65 77 22 20 2b } //01 00  + "fhew" +
		$a_01_2 = {26 20 22 68 72 62 73 22 20 2b } //00 00  & "hrbs" +
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}