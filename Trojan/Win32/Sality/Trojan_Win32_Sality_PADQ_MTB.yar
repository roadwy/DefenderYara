
rule Trojan_Win32_Sality_PADQ_MTB{
	meta:
		description = "Trojan:Win32/Sality.PADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 f2 ea 19 a1 ed ff c6 0f bf c6 2a ef 88 d8 00 fd 3a ea 69 cc 54 2d da 18 fe c2 8d 05 cf f9 ff ff 85 c9 c6 c6 3f c6 c5 e4 2d 23 08 00 00 74 09 } //1
		$a_01_1 = {f3 f7 c1 6b f5 14 5a 8a f7 03 e0 81 ff f4 b1 00 00 74 02 23 f0 81 ec ab f1 ff ff 8a d6 c7 c3 ba a0 75 d2 0c 96 84 ee 84 c0 0f af cf 42 81 fb 35 04 00 00 0f 82 85 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}