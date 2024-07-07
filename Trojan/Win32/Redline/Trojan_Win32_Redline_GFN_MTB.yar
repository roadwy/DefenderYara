
rule Trojan_Win32_Redline_GFN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 03 0d 90 01 04 0f bf 05 90 01 04 99 2b c1 66 a3 90 01 04 8b 15 90 01 04 83 f2 1c 88 55 e6 a1 90 01 04 03 45 94 66 89 45 d8 8b 8d 90 01 04 83 e9 90 01 01 89 8d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GFN_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 0a 8b 45 90 01 01 99 be 90 01 04 f7 fe 8b 45 90 01 01 0f be 14 10 6b d2 28 81 e2 90 01 04 33 ca 88 4d 90 01 01 0f be 45 90 01 01 0f be 4d 90 01 01 03 c1 8b 55 90 01 01 03 55 90 01 01 88 02 0f be 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f be 11 2b d0 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}