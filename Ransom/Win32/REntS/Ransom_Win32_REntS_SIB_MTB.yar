
rule Ransom_Win32_REntS_SIB_MTB{
	meta:
		description = "Ransom:Win32/REntS.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 19 00 09 00 00 0a 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //vssadmin.exe Delete Shadows /All /Quiet  0a 00 
		$a_80_1 = {48 6f 77 5f 44 65 63 72 79 70 74 5f 46 69 6c 65 73 2e 68 74 61 } //How_Decrypt_Files.hta  0a 00 
		$a_00_2 = {4e 41 50 4f 4c 45 4f 4e 20 44 45 43 52 59 50 54 45 52 } //01 00 
		$a_80_3 = {2e 6e 61 70 6f 6c 65 6f 6e } //.napoleon  01 00 
		$a_80_4 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 2c 20 77 72 69 74 65 20 75 73 20 74 6f 20 74 68 65 20 65 2d 6d 61 69 6c } //If you want to restore files, write us to the e-mail  01 00 
		$a_80_5 = {61 74 74 61 63 68 20 74 6f 20 65 6d 61 69 6c 20 33 20 63 72 79 70 74 65 64 20 66 69 6c 65 73 2e 20 28 66 69 6c 65 73 20 68 61 76 65 20 74 6f 20 62 65 20 6c 65 73 73 20 74 68 61 6e 20 32 20 4d 42 29 } //attach to email 3 crypted files. (files have to be less than 2 MB)  01 00 
		$a_80_6 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 62 75 79 20 74 68 65 20 73 70 65 63 69 61 6c 20 73 6f 66 74 77 61 72 65 } //To decrypt your files you need to buy the special software  01 00 
		$a_80_7 = {6f 72 61 63 6c 65 2e 65 78 65 } //oracle.exe  01 00 
		$a_80_8 = {73 71 6c 73 65 72 76 72 2e 65 78 65 } //sqlservr.exe  00 00 
	condition:
		any of ($a_*)
 
}