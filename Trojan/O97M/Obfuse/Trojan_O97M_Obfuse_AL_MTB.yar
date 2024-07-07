
rule Trojan_O97M_Obfuse_AL_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.AL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 } //1 = Environ(
		$a_01_1 = {2b 20 43 68 72 28 43 4c 6e 67 28 28 77 64 54 61 62 6c 65 46 6f 72 6d 61 74 57 65 62 32 20 58 6f 72 20 77 64 4b 65 79 46 37 29 29 29 20 2b } //1 + Chr(CLng((wdTableFormatWeb2 Xor wdKeyF7))) +
		$a_01_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 } //1 = Join(Array(
		$a_01_3 = {28 77 64 4c 61 79 6f 75 74 4d 6f 64 65 47 72 69 64 20 58 6f 72 20 77 64 4f 4d 61 74 68 48 6f 72 69 7a 41 6c 69 67 6e 4c 65 66 74 29 } //1 (wdLayoutModeGrid Xor wdOMathHorizAlignLeft)
		$a_01_4 = {28 28 77 64 54 61 62 6c 65 46 6f 72 6d 61 74 57 65 62 32 20 58 6f 72 20 77 64 4b 65 79 46 37 29 29 29 20 2b 20 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 20 28 } //1 ((wdTableFormatWeb2 Xor wdKeyF7))) + ChrW(CLng((Not (
		$a_01_5 = {43 68 72 28 43 4c 6e 67 28 28 77 64 42 61 73 65 6c 69 6e 65 41 6c 69 67 6e 54 6f 70 20 4f 72 20 77 64 46 69 65 6c 64 46 6f 72 6d 44 72 6f 70 44 6f 77 6e 29 29 29 20 2b 20 43 68 72 28 43 4c 6e 67 28 28 41 73 63 57 28 22 6c 22 29 29 29 29 } //1 Chr(CLng((wdBaselineAlignTop Or wdFieldFormDropDown))) + Chr(CLng((AscW("l"))))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}