
rule Trojan_Win32_Dridex_AT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  3
		$a_80_1 = {68 52 65 61 63 68 61 70 70 65 61 72 2e 31 35 32 39 43 68 72 6f 6d 69 75 6d 46 61 63 65 62 6f 6f 6b 2c } //hReachappear.1529ChromiumFacebook,  3
		$a_80_2 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //SHEnumerateUnreadMailAccountsW  3
		$a_80_3 = {41 74 74 61 63 68 54 68 72 65 61 64 49 6e 70 75 74 } //AttachThreadInput  3
		$a_80_4 = {51 75 65 72 79 55 73 65 72 73 4f 6e 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //QueryUsersOnEncryptedFile  3
		$a_80_5 = {53 63 72 6f 6c 6c 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 41 } //ScrollConsoleScreenBufferA  3
		$a_80_6 = {70 32 35 6d 65 6e 75 2c 71 75 69 63 6b 65 72 2c 47 77 69 6c 6c 69 65 73 69 74 65 73 64 65 78 74 65 72 61 6e 64 } //p25menu,quicker,Gwilliesitesdexterand  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}