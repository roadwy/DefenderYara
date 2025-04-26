
rule Trojan_Win32_Redline_HW_MTB{
	meta:
		description = "Trojan:Win32/Redline.HW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b0 74 f6 24 17 30 04 0b 41 39 ce 75 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}