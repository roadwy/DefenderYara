
rule Trojan_Win32_Stealerc_MBEU_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.MBEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8b f0 8b f0 33 db 33 f6 33 f6 8b de 8b db 33 f3 80 07 90 01 01 8b c0 8b c0 33 c6 8b f0 8b f6 33 f6 8b db 8b f6 33 c3 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}