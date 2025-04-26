
rule Trojan_BAT_RedLine_RDL_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 31 39 64 35 61 38 32 2d 35 38 66 65 2d 34 63 66 36 2d 62 38 63 36 2d 65 32 31 35 38 34 36 38 31 39 34 66 } //1 319d5a82-58fe-4cf6-b8c6-e2158468194f
		$a_01_1 = {58 50 64 72 69 76 65 72 } //1 XPdriver
		$a_01_2 = {50 00 66 00 72 00 57 00 59 00 6e 00 6e 00 47 00 49 00 78 00 50 00 69 00 56 00 6a 00 38 00 74 00 68 00 56 00 2e 00 6f 00 56 00 55 00 56 00 61 00 70 00 39 00 72 00 63 00 47 00 4b 00 4b 00 44 00 6d 00 70 00 52 00 4a 00 50 00 } //1 PfrWYnnGIxPiVj8thV.oVUVap9rcGKKDmpRJP
		$a_01_3 = {64 38 5a 48 45 48 41 47 79 72 4a 36 32 6e 30 4e 34 64 } //1 d8ZHEHAGyrJ62n0N4d
		$a_01_4 = {59 4f 6b 30 4b 4d 79 62 46 66 36 57 56 72 31 61 38 52 } //1 YOk0KMybFf6WVr1a8R
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}