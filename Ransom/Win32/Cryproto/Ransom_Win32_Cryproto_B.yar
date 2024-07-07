
rule Ransom_Win32_Cryproto_B{
	meta:
		description = "Ransom:Win32/Cryproto.B,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 90 01 01 6b 00 90 00 } //20
		$a_01_1 = {68 02 9f e6 6a e8 } //20
		$a_03_2 = {a8 01 74 09 d1 e8 35 90 01 04 eb 90 00 } //20
		$a_03_3 = {68 c8 af 00 00 ff 15 90 01 04 8b 0d 90 01 04 6b c9 64 b8 73 b2 e7 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*20+(#a_03_2  & 1)*20+(#a_03_3  & 1)*10) >=60
 
}