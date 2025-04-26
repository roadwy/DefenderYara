
rule Trojan_O97M_Obfuse_BR{
	meta:
		description = "Trojan:O97M/Obfuse.BR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 } //1 Sub AutoClose()
		$a_00_2 = {53 68 61 70 65 73 28 } //1 Shapes(
		$a_00_3 = {53 68 65 6c 6c } //1 Shell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}