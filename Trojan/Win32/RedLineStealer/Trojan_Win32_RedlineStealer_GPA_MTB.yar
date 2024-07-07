
rule Trojan_Win32_RedlineStealer_GPA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 33 c0 8b f3 8b c6 33 de 80 2f 90 01 01 33 d8 33 de 8b c3 33 db 8b c3 8b c6 33 d8 8b de 33 db f6 2f 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}