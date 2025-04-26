
rule Ransom_Win32_Teerac_I{
	meta:
		description = "Ransom:Win32/Teerac.I,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 ff 24 95 } //10
		$a_01_1 = {8b 45 08 ff 30 ff d7 } //10
		$a_01_2 = {8b 4d 08 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d7 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Ransom_Win32_Teerac_I_2{
	meta:
		description = "Ransom:Win32/Teerac.I,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 57 ff 24 95 } //10
		$a_01_1 = {8b 44 24 34 ff 30 ff d5 } //10
		$a_01_2 = {8b 4c 24 34 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d5 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Ransom_Win32_Teerac_I_3{
	meta:
		description = "Ransom:Win32/Teerac.I,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 72 5c 74 6f 72 72 5c 6c 69 62 72 65 73 73 6c 2d 32 2e 33 2e 31 5c 73 73 6c 5c 73 73 6c 5f 6c 69 62 2e 63 } //10 tor\torr\libressl-2.3.1\ssl\ssl_lib.c
		$a_01_1 = {65 79 75 69 6f 61 } //10 eyuioa
		$a_01_2 = {71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e } //10 qwrtpsdfghjklzxcvbn
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Ransom_Win32_Teerac_I_4{
	meta:
		description = "Ransom:Win32/Teerac.I,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 2e 5c 2e 2e 5c 73 6f 75 72 63 65 73 5c 65 78 74 2d 6c 69 62 73 5c 6c 69 62 74 6f 6d 63 72 79 70 74 5c 63 69 70 68 65 72 73 5c 61 65 73 } //10 ..\..\sources\ext-libs\libtomcrypt\ciphers\aes
		$a_01_1 = {65 79 75 69 6f 61 } //10 eyuioa
		$a_01_2 = {71 77 72 74 70 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e } //10 qwrtpsdfghjklzxcvbn
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}