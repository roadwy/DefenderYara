
rule Backdoor_Win32_Manuscrypt_AM_MTB{
	meta:
		description = "Backdoor:Win32/Manuscrypt.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 54 24 30 89 4c 24 34 c7 44 24 38 2f 00 25 00 c7 44 24 3c 64 00 2e 00 c7 44 24 44 6d 00 6c 00 c7 44 24 50 74 00 70 00 c7 44 24 54 73 00 3a 00 c7 44 24 58 2f 00 2f 00 c7 44 24 5c 76 00 2e 00 c7 44 24 60 78 00 79 00 c7 44 24 64 7a 00 67 00 } //1
		$a_01_1 = {50 8d 75 c4 c6 45 e4 43 c6 45 e5 72 c6 45 e6 65 c6 45 e7 61 c6 45 e8 74 c6 45 e9 65 88 5d ea c6 45 d4 57 c6 45 d5 69 c6 45 d6 6e c6 45 d7 33 c6 45 d8 32 c6 45 d9 5f c6 45 da 50 c6 45 db 72 c6 45 dc 6f c6 45 dd 63 c6 45 de 65 c6 45 df 73 c6 45 e0 73 88 5d e1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}