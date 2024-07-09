
rule Trojan_O97M_Obfuse_BE{
	meta:
		description = "Trojan:O97M/Obfuse.BE,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {0d 0a 53 68 65 6c 6c } //1
		$a_00_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_00_2 = {20 28 4b 65 79 53 74 72 69 6e 67 28 } //1  (KeyString(
		$a_00_3 = {20 2b 20 4b 65 79 53 74 72 69 6e 67 28 } //1  + KeyString(
		$a_00_4 = {28 30 29 20 3d 20 } //1 (0) = 
		$a_00_5 = {28 31 29 20 3d 20 } //1 (1) = 
		$a_02_6 = {44 69 6d 20 [0-0f] 28 32 29 0d 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=6
 
}