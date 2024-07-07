
rule Trojan_Win32_Redline_LL_MTB{
	meta:
		description = "Trojan:Win32/Redline.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 85 90 01 04 0f b6 8d 90 01 04 8b 85 90 01 04 33 d2 f7 75 90 01 01 0f b6 92 90 01 04 33 ca 88 8d 90 01 04 8b 45 90 01 01 03 85 90 01 04 8a 08 88 8d 90 01 04 0f b6 95 90 01 04 8b 45 90 01 01 03 85 90 01 04 0f b6 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}