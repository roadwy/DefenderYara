
rule Ransom_Win32_Mambretor_A{
	meta:
		description = "Ransom:Win32/Mambretor.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 44 43 32 32 5c 6e 65 74 70 61 73 73 2e 65 78 65 } //10 C:\DC22\netpass.exe
		$a_00_1 = {6e 65 74 20 75 73 65 72 20 2f 61 64 64 20 6d 79 74 68 62 75 73 74 65 72 73 } //10 net user /add mythbusters
		$a_01_2 = {68 00 64 00 30 00 00 00 73 74 61 72 74 20 68 61 72 64 20 64 72 69 76 65 20 65 6e 63 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Ransom_Win32_Mambretor_A_2{
	meta:
		description = "Ransom:Win32/Mambretor.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 77 38 38 39 39 30 31 36 36 35 40 79 61 6e 64 65 78 2e 63 6f 6d 29 } //4 (w889901665@yandex.com)
		$a_01_1 = {59 6f 75 20 61 72 65 20 48 61 63 6b 65 64 20 21 21 21 21 } //1 You are Hacked !!!!
		$a_01_2 = {59 6f 75 72 20 48 2e 44 2e 44 20 45 6e 63 72 79 70 74 65 64 20 2c 20 43 6f 6e 74 61 63 74 20 55 73 20 46 6f 72 20 44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 Your H.D.D Encrypted , Contact Us For Decryption Key
		$a_03_3 = {59 4f 55 52 49 44 3a 20 31 32 33 90 02 10 00 00 00 00 90 02 10 70 61 73 73 77 6f 72 64 20 69 6e 63 6f 72 72 65 63 74 90 00 } //2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=6
 
}