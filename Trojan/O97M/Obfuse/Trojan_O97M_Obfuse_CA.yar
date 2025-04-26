
rule Trojan_O97M_Obfuse_CA{
	meta:
		description = "Trojan:O97M/Obfuse.CA,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 53 68 65 6c 6c 28 } //1 .Shell(
		$a_02_1 = {20 3d 20 41 72 72 61 79 28 [0-10] 2c 20 [0-10] 2c 20 [0-10] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 20 5f } //1
		$a_02_2 = {2e 53 68 61 70 65 73 28 [0-10] 20 2b } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_O97M_Obfuse_CA_2{
	meta:
		description = "Trojan:O97M/Obfuse.CA,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 53 68 61 70 65 73 28 90 1d 15 00 20 2b 20 22 90 1d 15 00 22 20 2b 20 90 1d 15 00 29 90 } //1
		$a_00_1 = {41 72 72 61 79 28 90 02 30 49 6e 74 65 72 61 63 74 69 6f 6e 90 05 30 0a 2e 21 40 23 20 5d 5b 5f 0d 0a 53 68 65 6c 6c 28 90 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}