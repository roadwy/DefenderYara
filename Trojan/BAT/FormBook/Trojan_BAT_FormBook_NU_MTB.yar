
rule Trojan_BAT_FormBook_NU_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 20 00 60 00 00 5d 06 08 20 00 60 00 00 5d 91 07 08 1f 16 5d 28 fd 01 00 06 61 06 08 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //1
		$a_01_1 = {01 57 df b6 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b0 00 00 00 24 00 00 00 97 00 00 00 67 02 00 00 f8 00 00 00 07 00 00 00 5e 01 00 00 04 00 00 00 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_NU_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {36 39 64 37 66 38 34 63 2d 61 36 37 31 2d 34 64 34 35 2d 39 38 30 30 2d 31 34 34 37 33 38 38 37 37 34 33 31 } //4 69d7f84c-a671-4d45-9800-144738877431
		$a_81_1 = {74 78 74 5f 63 50 57 5f 70 61 73 73 77 64 } //1 txt_cPW_passwd
		$a_81_2 = {74 78 74 5f 4c 6f 67 69 6e 5f 75 73 65 72 6e 61 6d 65 } //1 txt_Login_username
		$a_81_3 = {74 78 74 5f 4c 6f 67 69 6e 5f 70 61 73 73 77 6f 72 64 } //1 txt_Login_password
		$a_81_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_5 = {62 75 74 74 6f 6e 45 6e 63 72 79 70 74 5f 43 6c 69 63 6b } //1 buttonEncrypt_Click
		$a_81_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=10
 
}