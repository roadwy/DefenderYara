
rule Ransom_Win32_Appokrypt_A{
	meta:
		description = "Ransom:Win32/Appokrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 2e 20 31 2d 32 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 28 70 6c 65 61 73 65 20 64 6f 6e 74 20 73 65 6e 64 20 66 69 6c 65 73 20 62 69 67 67 65 72 20 74 68 61 6e 20 31 20 4d 42 29 } //01 00  2. 1-2 encrypted files (please dont send files bigger than 1 MB)
		$a_03_1 = {33 ff 33 f6 eb 06 8d 9b 00 00 00 00 8b 86 90 01 04 50 8d 8c 24 90 01 02 00 00 51 ff 90 01 01 85 c0 74 05 bf 01 00 00 00 83 c6 04 83 fe 34 72 de 85 ff 90 00 } //01 00 
		$a_00_2 = {72 65 63 6f 76 65 72 79 68 65 6c 70 40 62 6b 2e 72 75 } //01 00  recoveryhelp@bk.ru
		$a_00_3 = {64 65 63 72 79 70 74 69 6f 6e 73 65 72 76 69 63 65 40 6d 61 69 6c 2e 72 75 } //00 00  decryptionservice@mail.ru
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}