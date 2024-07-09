
rule Trojan_O97M_Obfuse_YC_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.YC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b 20 43 68 72 28 52 65 70 6c 61 63 65 28 22 [0-0a] 22 2c 20 22 [0-0a] 22 2c 20 [0-05] 29 20 2d 20 [0-05] 29 } //1
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } //1 CreateObject("WScript.Shell").Run
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}