
rule Trojan_O97M_Obfuse_R{
	meta:
		description = "Trojan:O97M/Obfuse.R,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 } //1 Shapes(1).TextFrame.TextRange.Text
		$a_01_1 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1 Private Sub Document_open()
		$a_03_2 = {53 68 65 6c 6c 28 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-20] 2c 20 [0-20] 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}