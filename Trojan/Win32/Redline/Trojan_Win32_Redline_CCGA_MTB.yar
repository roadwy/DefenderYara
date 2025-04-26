
rule Trojan_Win32_Redline_CCGA_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f4 01 f6 d4 d0 cc 8a 04 33 32 c4 32 07 88 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}