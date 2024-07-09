
rule TrojanDownloader_O97M_Obfuse_JX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 74 70 3a 2f 2f 62 69 22 2c 20 22 [0-09] 22 29 2c } //1
		$a_01_1 = {53 68 65 6c 6c 20 28 } //1 Shell (
		$a_01_2 = {74 68 69 72 64 20 3d 20 28 74 68 69 72 64 20 2b 20 66 69 72 73 74 28 73 65 63 6f 6e 64 29 20 2b 20 66 6f 75 72 74 68 28 73 65 63 6f 6e 64 20 4d 6f 64 20 4c 65 6e 28 50 61 73 73 77 6f 72 64 29 29 29 20 4d 6f 64 20 32 35 36 } //1 third = (third + first(second) + fourth(second Mod Len(Password))) Mod 256
		$a_01_3 = {66 6f 75 72 74 68 28 73 65 63 6f 6e 64 29 20 3d 20 66 6f 75 72 74 68 28 73 65 63 6f 6e 64 29 20 58 6f 72 20 66 69 72 73 74 28 54 65 6d 70 20 2b 20 66 69 72 73 74 28 28 74 68 69 72 64 20 2b 20 66 69 72 73 74 28 74 68 69 72 64 29 29 20 4d 6f 64 20 32 35 34 29 29 } //1 fourth(second) = fourth(second) Xor first(Temp + first((third + first(third)) Mod 254))
		$a_01_4 = {3d 20 53 74 72 43 6f 6e 76 28 50 61 73 73 77 6f 72 64 2c 20 76 62 46 72 6f 6d 55 6e 69 63 6f 64 65 29 } //1 = StrConv(Password, vbFromUnicode)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}