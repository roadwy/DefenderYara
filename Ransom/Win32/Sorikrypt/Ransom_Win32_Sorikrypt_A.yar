
rule Ransom_Win32_Sorikrypt_A{
	meta:
		description = "Ransom:Win32/Sorikrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 70 33 6e 53 4f 75 72 63 33 20 58 30 72 31 35 37 2c 20 6d 6f 74 68 65 72 66 75 63 6b 65 72 21 } //1 0p3nSOurc3 X0r157, motherfucker!
		$a_01_1 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Attention! All your files were encrypted!
		$a_03_2 = {b9 19 00 00 00 bb 01 00 00 00 d3 e3 23 d8 74 2d 80 c1 41 88 0d 90 01 02 40 00 80 e9 41 c7 05 90 01 02 40 00 3a 5c 2a 2e 90 00 } //1
		$a_01_3 = {83 fa 10 75 02 33 d2 ac 32 04 1a aa 42 49 75 f0 61 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}