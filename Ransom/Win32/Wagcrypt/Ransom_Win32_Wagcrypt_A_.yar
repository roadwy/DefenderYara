
rule Ransom_Win32_Wagcrypt_A_{
	meta:
		description = "Ransom:Win32/Wagcrypt.A!!Wagcrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 6c 63 6f 6d 65 20 74 6f 20 6d 79 20 52 61 6e 73 6f 6d 77 61 72 65 21 } //01 00  Welcome to my Ransomware!
		$a_01_1 = {49 6e 20 6f 72 64 65 72 20 74 6f 20 68 61 76 65 20 72 65 6c 61 74 69 6f 6e 73 68 69 70 20 77 69 74 68 20 75 73 2c 20 61 6e 64 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 3b } //01 00  In order to have relationship with us, and pay the ransom;
		$a_01_2 = {7a 58 7a 2e 68 74 6d 6c } //02 00  zXz.html
		$a_01_3 = {b8 ab aa aa 2a f7 ef c1 fa 02 8b fa c1 ef 1f 03 fa } //05 00 
	condition:
		any of ($a_*)
 
}