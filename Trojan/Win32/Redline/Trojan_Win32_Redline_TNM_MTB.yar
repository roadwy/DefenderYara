
rule Trojan_Win32_Redline_TNM_MTB{
	meta:
		description = "Trojan:Win32/Redline.TNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 f0 31 c0 80 2f 90 01 01 31 f3 31 de 89 db 89 c0 31 f6 89 f0 80 07 90 01 01 89 de 89 c6 89 f6 31 d8 89 c6 31 c3 31 f0 89 f6 31 f0 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}