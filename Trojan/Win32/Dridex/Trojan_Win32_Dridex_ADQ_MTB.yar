
rule Trojan_Win32_Dridex_ADQ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 52 67 70 6d 64 6c 77 77 57 64 65 } //FFRgpmdlwwWde  3
		$a_80_1 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  3
		$a_80_2 = {74 6f 63 6f 75 6c 64 4d 6f 7a 69 6c 6c 61 73 63 6f 74 74 50 } //tocouldMozillascottP  3
		$a_80_3 = {6d 75 6c 74 69 2d 70 72 6f 63 65 73 73 75 73 65 73 74 41 66 74 65 72 62 79 6d 61 72 74 69 6e } //multi-processusestAfterbymartin  3
		$a_80_4 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  3
		$a_80_5 = {61 74 74 61 63 6b 65 72 69 6e 69 6e 77 68 69 63 68 67 5a 61 } //attackerininwhichgZa  3
		$a_80_6 = {63 68 65 73 74 65 72 4c 69 6e 75 78 2e 34 33 4d 6d 61 69 6e 39 53 } //chesterLinux.43Mmain9S  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}