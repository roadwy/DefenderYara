
rule Trojan_Win32_Redline_AHSY_MTB{
	meta:
		description = "Trojan:Win32/Redline.AHSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c9 0b f4 d4 a0 91 8e 90 90 90 03 03 88 d3 a0 91 3f 05 fb f4 d4 a0 91 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}