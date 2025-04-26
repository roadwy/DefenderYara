
rule Trojan_Win32_Dridex_AC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  3
		$a_80_1 = {43 72 65 61 74 65 41 73 79 6e 63 42 69 6e 64 43 74 78 45 78 } //CreateAsyncBindCtxEx  3
		$a_80_2 = {52 70 63 53 65 72 76 65 72 55 73 65 50 72 6f 74 73 65 71 41 } //RpcServerUseProtseqA  3
		$a_80_3 = {50 61 74 68 52 65 6d 6f 76 65 42 6c 61 6e 6b 73 41 } //PathRemoveBlanksA  3
		$a_80_4 = {4c 6f 6f 6b 75 70 49 63 6f 6e 49 64 46 72 6f 6d 44 69 72 65 63 74 6f 72 79 45 78 } //LookupIconIdFromDirectoryEx  3
		$a_80_5 = {53 63 72 6f 6c 6c 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 41 } //ScrollConsoleScreenBufferA  3
		$a_80_6 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //SHEnumerateUnreadMailAccountsW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}