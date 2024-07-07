
rule Trojan_Win32_RedLine_KAN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 f7 8a 82 90 01 04 30 04 19 41 3b ce 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}