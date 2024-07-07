
rule Trojan_Win32_Redline_GMC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 8b c0 80 07 90 01 01 80 2f 90 01 01 f6 2f 47 e2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}