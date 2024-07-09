
rule Trojan_O97M_Obfuse_BV{
	meta:
		description = "Trojan:O97M/Obfuse.BV,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 64 5f 66 69 78 20 73 62 31 2c 20 61 72 67 31 2c 20 70 65 72 32 } //1 red_fix sb1, arg1, per2
		$a_01_1 = {64 6f 63 5f 70 72 69 6e 74 5f 62 6f 64 79 20 46 6f 72 6d 31 2e 54 65 78 74 31 } //1 doc_print_body Form1.Text1
		$a_02_2 = {53 68 65 6c 6c 20 [0-20] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}