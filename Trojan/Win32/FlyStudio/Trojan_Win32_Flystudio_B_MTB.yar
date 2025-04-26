
rule Trojan_Win32_Flystudio_B_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 07 8b 4f 04 66 81 fe a0 72 3b e4 8d bf 04 00 00 00 33 d2 e9 4d 0f fc ff ff d0 } //1
		$a_01_1 = {66 0f be da 0f cb 5b 5f 8b e5 0f bf ef 87 ed 5d e9 4c 4c ed fe } //1
		$a_01_2 = {d0 c2 66 d3 c0 66 c1 f0 d9 80 ea a1 d0 ca 80 ea 77 66 2d 58 5f 66 0f a4 e0 71 32 da 66 c1 e8 89 66 0f a4 e8 7a 66 0f be c1 66 0f b6 04 14 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}