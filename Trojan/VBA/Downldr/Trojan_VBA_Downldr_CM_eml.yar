
rule Trojan_VBA_Downldr_CM_eml{
	meta:
		description = "Trojan:VBA/Downldr.CM!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 46 6f 74 6f 73 50 72 6f 64 75 63 74 6f 73 5c 52 65 70 63 6f 6e 90 0a 38 00 72 75 74 61 } //1
		$a_03_1 = {55 6c 6d 61 5c 52 65 70 63 6f 6e 5f 35 37 5c 90 0a 28 00 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 63 3a 5c } //1
		$a_03_2 = {2e 67 65 74 62 61 73 65 6e 61 6d 65 28 90 0a 64 00 6c 6f 67 46 69 6c 65 6e 61 6d 65 20 3d 20 22 43 3a 5c 74 65 6d 70 5c 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1
		$a_03_3 = {3d 20 57 73 68 53 68 65 6c 6c 2e 52 75 6e 28 22 70 69 6e 67 20 2d 6e 20 31 20 22 20 26 20 22 [0-19] 22 2c 20 30 2c 20 54 72 75 65 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}