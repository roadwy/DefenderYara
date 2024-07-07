
rule Trojan_Win32_Redline_ASBJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d8 8b c3 8b c3 8b d8 80 07 90 01 01 8b d8 33 d8 8b f6 33 c3 8b db 33 de 8b de 33 f3 8b c0 80 2f 90 01 01 33 f6 8b d8 8b c0 33 db 33 f0 8b d8 8b de 8b f3 8b d8 f6 2f 47 e2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}