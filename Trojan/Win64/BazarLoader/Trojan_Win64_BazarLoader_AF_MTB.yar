
rule Trojan_Win64_BazarLoader_AF_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_80_0 = {48 83 ec 58 c7 44 24 40 3f 10 f5 27 45 33 db c7 44 24 44 18 33 94 55 45 8b d1 8b 44 24 40 44 88 5c 24 48 8a 44 24 48 84 c0 75 1b } //H��X�D$@?�'E3��D$D3�UE�ыD$@D�\$H�D$H��u  10
		$a_80_1 = {53 74 61 72 74 57 } //StartW  3
		$a_80_2 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //ActivateKeyboardLayout  3
		$a_80_3 = {47 65 74 54 65 78 74 45 78 74 65 6e 74 50 6f 69 6e 74 33 32 41 } //GetTextExtentPoint32A  3
		$a_80_4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //GetCommandLineA  3
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}