
rule Trojan_Win32_RedLine_MBEZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d8 33 f0 8b de 80 07 90 01 01 8b c0 8b f6 33 f0 33 de 33 db 8b f6 8b f6 33 c0 8b f6 80 2f 90 01 01 8b c3 33 f0 33 de 33 db 8b f0 33 c6 8b c0 8b c0 8b db f6 2f 47 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}