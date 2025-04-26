
rule Trojan_Win32_Redline_GMU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 80 34 03 ?? ff d7 6a 00 ff d6 8b 44 24 ?? 6a 00 80 34 03 } //10
		$a_03_1 = {8b c1 c1 e8 ?? 33 c1 69 c8 ?? ?? ?? ?? 33 f1 3b d7 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}