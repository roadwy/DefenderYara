
rule Ransom_Win32_LockScreen_DD{
	meta:
		description = "Ransom:Win32/LockScreen.DD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 40 9c 00 00 8d 85 70 c6 fe ff 50 e8 ?? ?? ?? ?? 85 c0 0f 84 d9 01 00 00 8b bd f0 fe ff ff c1 ef 02 0f 84 a8 01 00 00 } //1
		$a_01_1 = {46 42 49 20 4f 6e 6c 69 6e 65 20 41 67 65 6e 74 20 76 2e 32 2e } //1 FBI Online Agent v.2.
		$a_01_2 = {41 72 74 69 63 6c 65 20 31 38 34 20 2d 20 50 6f 72 6e 6f 67 72 61 70 68 79 } //1 Article 184 - Pornography
		$a_01_3 = {6d 6f 6e 65 79 70 61 63 6b 5f 63 61 72 64 5f 6e 75 6d 62 65 72 3d } //1 moneypack_card_number=
		$a_01_4 = {41 66 74 65 72 20 70 61 79 69 6e 67 20 74 68 65 20 66 69 6e 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 69 6c 6c 20 62 65 20 75 6e 6c 6f 63 6b 65 64 } //1 After paying the fine your computer will be unlocked
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}