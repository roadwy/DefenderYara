
rule Trojan_Win32_Napolar_gen_A{
	meta:
		description = "Trojan:Win32/Napolar.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 04 3b 02 c2 8a b0 90 01 03 00 88 b1 90 01 03 00 88 90 90 90 01 03 00 fe c1 75 da 61 c9 c2 08 00 55 8b ec 60 8b 7d 0c 8b 75 08 85 ff 74 44 b8 00 00 00 00 8b d0 8b ca 8b d9 90 00 } //1
		$a_03_1 = {02 04 3b 02 c2 8a b0 90 01 03 00 88 b1 90 01 03 00 88 90 90 90 01 03 00 fe c1 75 da 61 c9 c2 08 00 55 8b ec 60 8b 7d 0c 8b 75 08 85 ff 74 41 33 c0 33 d2 33 c9 33 db 90 00 } //1
		$a_03_2 = {ff 75 0c ff 75 08 e8 58 00 00 00 c9 c2 10 00 55 8b ec 60 b8 fc fd fe ff b9 40 00 00 00 89 04 90 01 04 00 2d 04 04 04 04 49 75 f1 33 c0 8b 7d 08 33 db 8b 75 0c eb 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}