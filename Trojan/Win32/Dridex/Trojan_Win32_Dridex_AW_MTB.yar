
rule Trojan_Win32_Dridex_AW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {b0 4a b1 24 8a 54 24 43 88 44 24 2b 88 d0 f6 e1 8a 4c 24 7f 88 84 24 98 00 00 00 8a 44 24 2b 38 c8 } //10
		$a_01_1 = {31 d2 ba 14 35 09 00 39 d0 77 2d 83 c0 01 83 c0 02 83 e8 02 cc 83 c0 02 83 e8 02 cc } //10
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AW_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6d 6f 7a 32 5f 73 6c 61 76 65 } //moz2_slave  3
		$a_80_1 = {54 65 73 74 41 72 72 61 79 2e 70 64 62 } //TestArray.pdb  3
		$a_80_2 = {44 65 63 69 6d 61 6c 40 62 6c 69 6e 6b } //Decimal@blink  3
		$a_80_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
		$a_80_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  3
		$a_80_5 = {4d 4f 5a 5f 41 53 53 45 52 54 5f 55 4e 52 45 41 43 48 41 42 4c 45 } //MOZ_ASSERT_UNREACHABLE  3
		$a_80_6 = {61 75 74 6f 6c 61 6e 64 2d 77 33 32 } //autoland-w32  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AW_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  3
		$a_80_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  3
		$a_80_2 = {49 6d 6d 53 65 74 4f 70 65 6e 53 74 61 74 75 73 } //ImmSetOpenStatus  3
		$a_80_3 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //SHEnumerateUnreadMailAccountsW  3
		$a_80_4 = {53 48 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 50 61 74 68 41 } //SHGetSpecialFolderPathA  3
		$a_80_5 = {50 61 74 68 52 65 6d 6f 76 65 42 6c 61 6e 6b 73 57 } //PathRemoveBlanksW  3
		$a_80_6 = {43 72 65 61 74 65 41 73 79 6e 63 42 69 6e 64 43 74 78 45 78 } //CreateAsyncBindCtxEx  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}