
rule Trojan_Win32_Zegost_DAL_MTB{
	meta:
		description = "Trojan:Win32/Zegost.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {b1 a4 ab 38 b5 32 0d c9 b8 ad e5 ab 69 89 6a ad fc f8 b2 d7 cc 93 35 5a 3d da 96 2d e8 a2 3e 49 07 45 ad 79 } //02 00 
		$a_01_1 = {12 28 38 9b 1f 71 be 5c 4a 92 e6 cf a7 35 b1 66 7d ca 13 66 55 a7 50 6f 42 94 3a b4 ab d5 ad 11 b3 8a c5 5a d5 ec 51 ad 51 71 } //00 00 
	condition:
		any of ($a_*)
 
}