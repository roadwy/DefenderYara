
rule Trojan_Win32_Ursnif_BD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ce 6b c9 90 01 01 2b cf 83 f8 90 01 01 a1 90 01 04 89 0d 90 00 } //1
		$a_02_1 = {0f b7 54 24 90 01 01 39 15 90 01 04 73 90 01 01 89 3d 90 01 04 2b 05 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 8d 94 18 90 01 04 8b 02 90 08 30 00 03 0d 90 01 04 89 0d 90 01 04 05 90 01 04 a3 90 01 04 89 02 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Ursnif_BD_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c5 03 f7 83 e8 52 0f b6 c0 0f af c7 69 d0 7f a4 00 00 b0 57 8a ca c0 e1 04 02 ca 2a c1 0f b6 c8 8d 04 11 69 c0 13 14 58 1e 2b d0 8b 44 24 10 05 7c 25 39 03 8d 14 50 a1 90 01 04 03 c7 03 d2 69 f8 7f a4 00 00 2b d1 0f b7 c6 8d 4a 9f 2b d6 81 ef 7b 36 03 00 88 0d 90 01 04 0f af f8 8d 43 ae 03 c2 0f b7 c0 8b d7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}