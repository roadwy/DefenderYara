
rule Ransom_Win32_Stylcrypt_A{
	meta:
		description = "Ransom:Win32/Stylcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 2c 20 66 72 69 65 6e 64 2c 20 50 6c 65 61 73 65 20 72 65 61 64 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 } //1 Hello, friend, Please read the following
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 2c 20 70 6c 65 61 73 65 20 64 6f 20 6e 6f 74 20 63 6c 6f 73 65 20 74 68 65 20 73 79 73 74 65 6d 2c 20 6f 72 20 6d 6f 64 69 66 79 20 74 68 65 20 65 78 74 65 6e 73 69 6f 6e 20 6e 61 6d 65 } //1 Your file has been locked, please do not close the system, or modify the extension name
		$a_01_2 = {47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 47 4f 41 54 } //1 GOATGOATGOATGOATGOATGOATGOATGOATGOATGOATGOATGOAT
		$a_01_3 = {2a 2e 53 74 69 6e 67 65 72 } //2 *.Stinger
		$a_01_4 = {45 2d 6d 61 69 6c 3a 68 61 63 6b 63 77 61 6e 64 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //2 E-mail:hackcwand@protonmail.com
		$a_01_5 = {41 62 6f 75 74 20 2e 53 74 69 6e 67 65 72 20 75 6e 6c 6f 63 6b 69 6e 67 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 74 78 74 } //2 About .Stinger unlocking instructions.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=5
 
}