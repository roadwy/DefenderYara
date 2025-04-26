
rule TrojanDownloader_O97M_Obfuse_BUR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BUR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 70 34 65 31 64 45 77 74 44 4f 38 58 52 67 57 28 29 20 41 73 20 43 75 72 72 65 6e 63 79 } //1 Function p4e1dEwtDO8XRgW() As Currency
		$a_01_1 = {43 61 6c 6c 20 7a 6e 77 43 72 6c } //1 Call znwCrl
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 62 69 6c 6f 6f 28 62 75 72 67 65 72 6f 72 67 61 6e 2c 20 62 6f 6e 75 73 73 68 6f 6f 74 29 } //1 Function biloo(burgerorgan, bonusshoot)
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 6e 69 6f 28 62 75 72 67 65 72 6f 72 67 61 6e 2c 20 62 6f 6e 75 73 73 68 6f 6f 74 29 } //1 Function nio(burgerorgan, bonusshoot)
		$a_01_4 = {71 6f 78 6e 77 6b 71 6e 68 66 73 68 68 69 6d 72 20 3d 20 22 2a 22 20 26 20 62 75 72 67 65 72 6f 72 67 61 6e 20 26 20 22 2a 22 } //1 qoxnwkqnhfshhimr = "*" & burgerorgan & "*"
		$a_01_5 = {44 69 6d 20 62 65 33 61 38 63 31 66 33 30 66 31 61 62 61 64 64 36 34 38 65 32 32 62 31 36 66 64 62 35 37 64 35 20 41 73 20 44 6f 75 62 6c 65 } //1 Dim be3a8c1f30f1abadd648e22b16fdb57d5 As Double
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}