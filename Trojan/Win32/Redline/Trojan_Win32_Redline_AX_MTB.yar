
rule Trojan_Win32_Redline_AX_MTB{
	meta:
		description = "Trojan:Win32/Redline.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 f7 0f be 04 2a 6b c0 a9 30 04 19 41 3b ce 72 eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}