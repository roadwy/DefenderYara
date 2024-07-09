
rule TrojanDropper_O97M_Obfuse_NK_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.NK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 74 20 23 31 2c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 43 68 65 63 6b 42 6f 78 31 2e 43 61 70 74 69 6f 6e } //1 Print #1, ThisDocument.CheckBox1.Caption
		$a_01_1 = {2e 54 61 67 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 4f 70 74 69 6f 6e 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e } //1 .Tag & ThisDocument.OptionButton1.Caption
		$a_01_2 = {4d 73 67 42 6f 78 20 22 45 72 72 6f 72 20 22 20 26 } //1 MsgBox "Error " &
		$a_01_3 = {50 69 63 41 72 72 61 79 20 3d 20 50 69 63 41 72 72 61 79 20 2b } //1 PicArray = PicArray +
		$a_01_4 = {51 20 3d 20 51 20 2b } //1 Q = Q +
		$a_01_5 = {2a 20 43 6f 73 28 } //1 * Cos(
		$a_03_6 = {3d 20 45 6e 76 69 72 6f 6e 24 28 49 6e 74 32 53 74 72 28 22 [0-35] 22 29 29 20 26 20 49 6e 74 32 53 74 72 28 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}