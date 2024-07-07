
rule Trojan_Win32_Redline_GTU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c c7 45 90 01 01 00 00 00 00 b8 90 01 04 99 33 c2 2b c2 89 45 d0 83 7d d0 d8 74 90 00 } //10
		$a_03_1 = {6b c9 28 c7 84 0d 90 01 04 b1 7b ff 28 ba 04 00 00 00 6b d2 09 c7 84 15 90 01 04 a6 c3 65 bf b8 04 00 00 00 6b c0 4b c7 84 05 90 01 04 12 02 ff 36 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}