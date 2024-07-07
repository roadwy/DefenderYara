
rule Trojan_Win32_Redline_ASAW_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d8 33 d8 8b c6 f6 17 8b db 33 c3 33 c6 80 07 90 01 01 33 c6 33 de 8b f6 80 2f 90 01 01 8b f0 33 d8 33 f3 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}