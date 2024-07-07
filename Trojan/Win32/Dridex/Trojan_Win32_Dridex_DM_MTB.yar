
rule Trojan_Win32_Dridex_DM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 b9 ca b1 66 8b 54 24 28 66 29 d1 66 89 4c 24 6a 0f b6 00 3d b8 } //10
		$a_01_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //3 FFPGGLBM.pdb
		$a_01_2 = {41 64 64 4a 6f 62 57 } //3 AddJobW
		$a_01_3 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //3 SHEnumerateUnreadMailAccountsW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=19
 
}
rule Trojan_Win32_Dridex_DM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {b9 f0 02 00 00 31 d2 f7 f1 89 85 0c fd ff ff 31 ff 3b bd 0c fd ff ff 73 3c 69 c7 f0 02 00 00 ff 75 2c 8d 94 06 70 02 } //10
		$a_80_1 = {48 65 68 2a 2e 62 69 68 69 6c 65 } //Heh*.bihile  3
		$a_80_2 = {68 49 5a 45 5f 68 54 48 4f 52 68 4f 5f 41 55 68 4c 45 5f 54 68 55 4e 41 42 68 45 } //hIZE_hTHORhO_AUhLE_ThUNABhE  3
		$a_80_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //gethostbyname  3
		$a_80_4 = {57 53 41 53 6f 63 6b 65 74 41 } //WSASocketA  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=20
 
}