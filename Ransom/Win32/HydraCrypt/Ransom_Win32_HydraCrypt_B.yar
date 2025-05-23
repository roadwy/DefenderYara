
rule Ransom_Win32_HydraCrypt_B{
	meta:
		description = "Ransom:Win32/HydraCrypt.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_01_0 = {8b 50 08 8b 48 20 8b 00 81 79 0c 33 00 32 00 75 ef } //1
		$a_03_1 = {30 06 46 0f af c1 ba ?? ?? ?? ?? ff 4d 0c 4a 03 c2 83 7d 0c 00 77 e9 } //1
		$a_01_2 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 } //1
		$a_01_3 = {81 38 73 00 79 00 75 12 81 78 04 73 00 74 00 75 09 81 78 08 65 00 6d 00 74 0c } //1
		$a_03_4 = {30 07 47 0f af c1 ba ?? ?? ?? ?? ff 4d 0c 03 c2 40 40 83 7d 0c 00 77 e8 } //1
		$a_03_5 = {30 07 47 0f af c1 68 ?? ?? ?? ?? 5a ff 4d 0c 03 c2 40 83 7d 0c 00 77 e8 } //1
		$a_01_6 = {c1 c0 07 0f be c9 33 c1 42 8a 0a 84 c9 75 f1 } //1
		$a_01_7 = {8a 07 32 c3 88 06 47 2b f2 49 75 f4 } //1
		$a_01_8 = {81 38 73 00 79 00 75 0e 81 78 04 73 00 74 00 75 05 39 48 08 74 0f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=3
 
}