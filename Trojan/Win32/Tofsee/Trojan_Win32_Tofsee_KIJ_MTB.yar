
rule Trojan_Win32_Tofsee_KIJ_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 10 8b 44 24 28 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 2c 3b 75 90 00 } //1
		$a_03_1 = {33 f5 31 74 24 10 8b 44 24 10 29 44 24 14 a1 94 eb 7a 00 3d 93 00 00 00 74 90 01 01 81 c3 47 86 c8 61 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}