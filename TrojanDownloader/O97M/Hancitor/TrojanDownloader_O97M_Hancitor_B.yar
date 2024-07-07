
rule TrojanDownloader_O97M_Hancitor_B{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 59 32 31 6b 4c 6d 56 34 5a 53 41 76 59 79 41 67 63 47 6c 75 5a 79 42 73 62 32 4e 68 62 47 68 76 63 33 51 67 4c 57 34 67 4d 54 41 77 49 43 59 6d 49 41 3d 3d 22 29 } //1 Shell StrConv(DecodeBase64("Y21kLmV4ZSAvYyAgcGluZyBsb2NhbGhvc3QgLW4gMTAwICYmIA==")
		$a_00_1 = {53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 58 44 59 75 63 47 6c 6d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 76 62 48 69 64 65 } //1 StrConv(DecodeBase64("XDYucGlm"), vbUnicode), vbHide
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}