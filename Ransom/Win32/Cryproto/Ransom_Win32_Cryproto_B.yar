
rule Ransom_Win32_Cryproto_B{
	meta:
		description = "Ransom:Win32/Cryproto.B,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 04 00 00 14 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 90 01 01 6b 00 90 00 } //14 00 
		$a_01_1 = {68 02 9f e6 6a e8 } //14 00 
		$a_03_2 = {a8 01 74 09 d1 e8 35 90 01 04 eb 90 00 } //0a 00 
		$a_03_3 = {68 c8 af 00 00 ff 15 90 01 04 8b 0d 90 01 04 6b c9 64 b8 73 b2 e7 45 90 00 } //00 00 
		$a_00_4 = {7e 15 00 00 54 e3 5d 66 41 64 64 b0 0a ef 14 77 3f 89 35 89 00 00 00 00 62 5d 04 00 00 a5 8f 03 80 5c 2e 00 00 a9 8f 03 80 00 00 01 00 32 00 18 00 52 } //61 6e 
	condition:
		any of ($a_*)
 
}