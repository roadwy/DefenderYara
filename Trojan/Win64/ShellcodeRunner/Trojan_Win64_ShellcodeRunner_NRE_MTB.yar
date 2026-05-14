
rule Trojan_Win64_ShellcodeRunner_NRE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_81_0 = {62 63 72 79 70 74 70 72 69 6d 69 74 69 76 65 73 2e 64 6c 6c } //1 bcryptprimitives.dll
		$a_81_1 = {70 6f 77 72 70 72 6f 66 2e 64 6c 6c } //1 powrprof.dll
		$a_81_2 = {42 69 6e 6a 65 63 74 2f 64 65 62 75 67 } //1 Binject/debug
		$a_81_3 = {47 6f 32 62 79 70 61 73 73 2f 6f 75 74 70 75 74 } //1 Go2bypass/output
		$a_81_4 = {6e 65 42 70 39 77 44 59 56 59 34 55 75 31 67 47 6c 72 4c 2b 49 4c 34 4a 65 5a 73 6c 7a 2b 68 47 45 41 6a 42 58 47 41 50 57 61 6b 3d } //1 neBp9wDYVY4Uu1gGlrL+IL4JeZslz+hGEAjBXGAPWak=
		$a_81_5 = {68 31 3a 63 49 41 4b 32 4e 4e 66 32 79 61 66 64 67 70 46 52 4e 4a 72 67 5a 4d 77 76 79 36 31 42 45 56 70 47 6f 48 63 32 6e 34 2f 79 57 73 3d } //2 h1:cIAK2NNf2yafdgpFRNJrgZMwvy61BEVpGoHc2n4/yWs=
		$a_81_6 = {68 31 3a 78 48 6d 73 34 67 63 70 65 31 59 45 37 41 33 79 49 6c 6c 4a 58 50 31 36 43 4d 41 47 75 71 77 4f 32 6c 58 31 6d 54 79 79 52 52 63 3d } //1 h1:xHms4gcpe1YE7A3yIllJXP16CMAGuqwO2lX1mTyyRRc=
		$a_81_7 = {63 72 79 70 74 42 6c 6f 63 6b 73 44 65 63 47 65 6e 65 72 69 63 } //1 cryptBlocksDecGeneric
		$a_81_8 = {43 6f 64 65 54 6f 53 68 65 6c 6c 44 6e 63 72 79 70 74 } //1 CodeToShellDncrypt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=10
 
}