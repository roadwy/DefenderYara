
rule Ransom_Win32_Converton_A{
	meta:
		description = "Ransom:Win32/Converton.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {26 65 6e 64 5f 63 72 79 70 74 5f 74 69 6d 65 3d 25 64 26 63 6f 75 6e 74 5f 66 69 6c 65 73 5f 63 72 79 70 74 65 64 3d 25 64 } //&end_crypt_time=%d&count_files_crypted=%d  1
		$a_80_1 = {5c 5c 3f 5c 25 73 25 63 25 63 25 63 25 63 25 63 25 63 } //\\?\%s%c%c%c%c%c%c  1
		$a_02_2 = {25 00 30 00 32 00 78 00 [0-08] 43 00 6f 00 76 00 65 00 72 00 74 00 6f 00 6e 00 [0-08] 25 00 78 00 25 00 78 00 25 00 78 00 25 00 78 00 } //2
		$a_02_3 = {25 30 32 78 [0-08] 43 6f 76 65 72 74 6f 6e [0-08] 25 78 25 78 25 78 25 78 } //2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=3
 
}