
rule Trojan_Win32_Redline_GJR_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 43 83 e0 03 8a 80 90 01 04 30 06 8b 45 f0 3b 5d 0c 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}