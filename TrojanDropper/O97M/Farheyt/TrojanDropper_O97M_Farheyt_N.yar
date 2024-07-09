
rule TrojanDropper_O97M_Farheyt_N{
	meta:
		description = "TrojanDropper:O97M/Farheyt.N,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 74 6d 70 22 [0-0f] 90 12 0f 00 20 3d 20 [0-0f] 26 [0-05] 72 74 66 22 [0-2f] 2b 20 90 1b 01 } //2
		$a_01_1 = {2b 20 22 66 68 65 77 22 20 2b } //1 + "fhew" +
		$a_01_2 = {26 20 22 68 72 62 73 22 20 2b } //1 & "hrbs" +
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}