
rule Trojan_Win32_Redline_GCC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 08 0f b6 92 90 01 04 33 ca 88 8d 90 01 04 8b 85 90 01 04 8a 88 90 01 04 88 8d 90 01 04 0f b6 95 90 01 04 8b 85 90 01 04 0f b6 88 90 01 04 03 ca 8b 95 90 01 04 88 8a 90 01 04 8a 85 90 01 04 88 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}