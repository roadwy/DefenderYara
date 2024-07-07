
rule Trojan_Win32_Redline_GDQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f3 8b c6 ba 90 01 04 83 e0 03 b9 90 01 04 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 04 50 e8 90 01 04 88 9e 90 01 04 46 59 81 fe 90 01 04 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}