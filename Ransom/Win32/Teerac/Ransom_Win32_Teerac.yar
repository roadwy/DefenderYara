
rule Ransom_Win32_Teerac{
	meta:
		description = "Ransom:Win32/Teerac,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f3 de bd 9f 07 8b d2 eb 06 81 c3 9d 8e b8 00 } //10
		$a_01_1 = {50 58 8b c0 33 d2 8b c0 87 14 24 8b c0 83 c4 04 8b c0 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}