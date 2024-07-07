
rule Trojan_Win32_Drixed_QD_MTB{
	meta:
		description = "Trojan:Win32/Drixed.QD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  3
		$a_80_1 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  3
		$a_80_2 = {50 61 74 68 52 65 6d 6f 76 65 42 6c 61 6e 6b 73 57 } //PathRemoveBlanksW  3
		$a_80_3 = {49 73 42 61 64 48 75 67 65 52 65 61 64 50 74 72 } //IsBadHugeReadPtr  3
		$a_80_4 = {51 75 65 72 79 55 73 65 72 73 4f 6e 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //QueryUsersOnEncryptedFile  3
		$a_80_5 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //SHEnumerateUnreadMailAccountsW  3
		$a_80_6 = {68 52 65 61 63 68 61 70 70 65 61 72 2e 31 35 32 39 43 68 72 6f 6d 69 75 6d 46 61 63 65 62 6f 6f 6b 2c } //hReachappear.1529ChromiumFacebook,  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}