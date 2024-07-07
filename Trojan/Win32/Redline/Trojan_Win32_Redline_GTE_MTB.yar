
rule Trojan_Win32_Redline_GTE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 c0 0f b6 0a 8b 45 c0 33 d2 be 04 00 00 00 f7 f6 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 c0 8a 4d eb 88 08 eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}