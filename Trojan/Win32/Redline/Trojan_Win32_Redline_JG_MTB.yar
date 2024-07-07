
rule Trojan_Win32_Redline_JG_MTB{
	meta:
		description = "Trojan:Win32/Redline.JG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 ba 00 00 00 00 f7 f5 c1 ea 02 b0 74 f6 24 17 30 04 0b 41 39 ce 75 e7 83 c4 7c 5b 5e 5f 5d c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}