
rule Trojan_Win32_Redline_XA_MTB{
	meta:
		description = "Trojan:Win32/Redline.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f7 0f be 04 2a 6b c0 d0 30 04 19 41 3b ce } //10
		$a_03_1 = {33 d2 8b c1 f7 f7 8a 04 2a 8a d0 02 c0 02 d0 c0 e2 90 01 01 30 14 19 41 3b ce 72 e6 90 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}