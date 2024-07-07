
rule Trojan_Win32_Redline_GTW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 bc 8a 02 88 45 c3 0f b6 4d c3 8b 45 bc 33 d2 f7 75 b4 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 bc 8a 4d eb 88 08 eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}