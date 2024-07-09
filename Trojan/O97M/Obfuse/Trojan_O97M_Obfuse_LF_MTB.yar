
rule Trojan_O97M_Obfuse_LF_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.LF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 22 65 79 52 52 78 59 53 6f 56 4f 4a 62 63 6d 41 46 64 77 41 6f 51 4e 56 44 43 6f 75 62 48 59 61 75 4d 67 54 6b 71 45 6e 4f 50 6f 69 56 57 78 57 59 48 74 77 48 79 42 61 51 64 4e 4f 49 64 72 68 77 6f 50 50 77 54 50 22 20 3d 20 22 59 4a 6d 5a 62 66 7a 67 45 53 57 54 4e 62 53 76 4b 47 44 48 63 70 65 6b 58 48 22 20 54 68 65 6e } //1 If "eyRRxYSoVOJbcmAFdwAoQNVDCoubHYauMgTkqEnOPoiVWxWYHtwHyBaQdNOIdrhwoPPwTP" = "YJmZbfzgESWTNbSvKGDHcpekXH" Then
		$a_03_1 = {52 65 70 6c 61 63 65 28 [0-08] 2c 20 22 [0-24] 22 2c 20 22 22 29 } //1
		$a_03_2 = {2e 52 75 6e 20 [0-0a] 2c 20 2d 31 } //1
		$a_01_3 = {45 41 20 3d 20 39 33 } //1 EA = 93
		$a_01_4 = {43 4c 5a 65 20 3d 20 36 30 } //1 CLZe = 60
		$a_01_5 = {49 6e 74 28 28 36 20 2a 20 52 6e 64 29 20 2b 20 31 29 } //1 Int((6 * Rnd) + 1)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}