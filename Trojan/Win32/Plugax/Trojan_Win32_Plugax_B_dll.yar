
rule Trojan_Win32_Plugax_B_dll{
	meta:
		description = "Trojan:Win32/Plugax.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6c 62 2e 64 6c 6c 00 } //1
		$a_01_1 = {85 c0 74 0b 8d 4d e8 51 68 3f 01 0f 00 eb 09 8d 55 e8 52 68 3f 00 0f 00 6a 00 68 } //1
		$a_03_2 = {33 c0 8b fb 6a 01 c1 e9 02 f3 ab 8b ca 6a 08 83 e1 03 68 90 01 04 f3 aa 8b 44 24 24 56 50 53 e8 90 00 } //1
		$a_01_3 = {83 e1 03 6a 00 f3 aa 8b ce 8b f3 8b c1 8b fa c1 e9 02 f3 a5 8b c8 6a 00 83 e1 03 52 6a 00 6a 00 f3 a4 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}