
rule Ransom_Win32_Nemty_AR_MTB{
	meta:
		description = "Ransom:Win32/Nemty.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {5c 76 69 72 75 62 69 6d 5f 65 73 68 6b 79 2e 6a 70 67 } //\virubim_eshky.jpg  0a 00 
		$a_80_1 = {53 49 47 41 52 45 54 41 2d 52 45 53 54 4f 52 45 2e 74 78 74 } //SIGARETA-RESTORE.txt  0a 00 
		$a_80_2 = {5c 52 65 6c 65 61 73 65 5c 53 49 47 41 52 45 54 41 2e 70 64 62 } //\Release\SIGARETA.pdb  01 00 
		$a_80_3 = {2e 53 49 47 41 52 45 54 41 } //.SIGARETA  01 00 
		$a_80_4 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 20 28 78 38 36 29 } //program files (x86)  01 00 
		$a_80_5 = {34 33 37 32 37 39 37 30 37 34 34 39 36 44 37 30 36 46 37 32 37 34 34 42 36 35 37 39 } //4372797074496D706F72744B6579  01 00 
		$a_80_6 = {70 6f 68 75 69 } //pohui  00 00 
		$a_00_7 = {5d 04 00 00 4d 29 04 80 5c 25 00 00 4e 29 04 80 00 00 01 00 04 00 0f 00 89 21 4c 61 7a 61 } //72 75 
	condition:
		any of ($a_*)
 
}