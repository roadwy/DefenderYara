
rule Trojan_Win32_Cridex_QLM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.QLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d1 c1 fa 05 c1 ea 1a 03 d1 c1 ea 06 81 e1 3f 00 00 80 7d 07 83 e9 01 83 c9 c0 41 33 c0 85 c9 } //10
		$a_01_1 = {56 53 55 8b e9 8b 5c 24 10 33 d2 89 55 00 89 55 04 89 55 08 89 55 0c 85 db 74 08 8b 74 24 14 85 f6 75 08 8b c5 5d 5b 5e c2 08 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}