
rule Trojan_Win32_Redline_CBYD_MTB{
	meta:
		description = "Trojan:Win32/Redline.CBYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 50 b8 90 01 04 83 c0 21 b9 60 01 00 00 42 e2 fd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}