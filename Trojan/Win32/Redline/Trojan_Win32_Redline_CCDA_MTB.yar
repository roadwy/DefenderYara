
rule Trojan_Win32_Redline_CCDA_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 33 de 90 01 01 c0 33 90 01 01 8b f6 90 01 04 8b c3 f6 2f 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}