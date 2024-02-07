
rule Trojan_O97M_Obfuse_SH_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.SH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 74 6f 62 6a 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 65 78 63 65 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //01 00  setobj=createobject("excel.application")
		$a_02_1 = {6f 62 6a 2e 64 64 65 69 6e 69 74 69 61 74 65 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 22 2c 22 63 3a 5c 90 02 0f 5c 90 02 0f 2e 76 62 65 90 00 } //01 00 
		$a_02_2 = {6f 70 65 6e 22 63 3a 5c 90 02 0f 5c 90 02 0f 2e 76 62 65 22 66 6f 72 6f 75 74 70 75 74 61 63 63 65 73 73 77 72 69 74 65 61 73 23 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}