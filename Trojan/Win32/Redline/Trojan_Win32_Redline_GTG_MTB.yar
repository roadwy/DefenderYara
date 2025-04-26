
rule Trojan_Win32_Redline_GTG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb 5b 33 d2 8b c1 f7 f3 02 d3 30 54 0d d0 41 83 f9 0e 72 ee } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}