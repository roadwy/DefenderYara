
rule Trojan_Win32_Redline_CCBD_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f0 8b d8 33 de 80 2f ?? 8b db 33 f3 8b c3 80 07 ?? 8b f0 8b f0 33 de f6 2f 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}