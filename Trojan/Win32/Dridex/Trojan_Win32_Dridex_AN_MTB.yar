
rule Trojan_Win32_Dridex_AN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 5c 24 18 4a 6b c7 2f 8b ca 2b c8 8a 04 1e 88 03 43 0f b7 c9 8b e9 89 5c 24 18 } //10
		$a_02_1 = {66 2b c6 66 83 c0 41 0f b7 d0 8b 44 24 14 8d 5a 1a 05 50 b3 06 01 02 db a3 90 01 04 89 84 2f 5a fa ff ff 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}