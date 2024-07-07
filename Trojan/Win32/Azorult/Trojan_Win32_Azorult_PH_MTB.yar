
rule Trojan_Win32_Azorult_PH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 88 90 01 03 00 f6 d1 2a c8 80 c1 02 80 f1 a2 80 e9 64 f6 d1 fe c9 88 88 90 01 03 00 40 83 f8 09 72 90 00 } //1
		$a_02_1 = {33 c2 8d 44 10 01 35 a4 00 00 00 2b c2 83 c0 47 8b c8 c1 e9 03 c1 e0 05 83 e1 1f 0b c8 81 e1 ff 00 00 00 2b ca 8b c1 c1 e8 04 83 e0 0f c1 e1 04 0b c1 25 ff 00 00 00 2b c2 2d bf 00 00 00 33 c2 48 8b c8 c1 e9 03 80 e1 1f c0 e0 05 0a c8 88 8a 90 01 03 00 42 83 fa 0f 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}