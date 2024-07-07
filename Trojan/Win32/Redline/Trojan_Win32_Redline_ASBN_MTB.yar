
rule Trojan_Win32_Redline_ASBN_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 de 8b c6 8b d8 80 2f 90 01 01 8b c3 8b de 8b f6 8b f0 33 de 33 f3 33 f6 33 c6 33 c6 80 07 90 01 01 8b d8 33 d8 33 f0 33 de 33 f6 8b f0 33 c6 8b f3 8b c6 f6 2f 47 e2 90 00 } //5
		$a_03_1 = {33 f3 8b f6 80 2f 90 01 01 33 de 8b db 8b c0 33 d8 8b c0 33 de 33 db 33 f6 33 f3 80 07 90 01 01 8b c6 33 de 33 c0 8b d8 8b d8 33 d8 33 c6 33 c3 8b c0 f6 2f 47 e2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}