
rule Trojan_Win32_Redline_GJJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 33 d0 a1 90 01 04 03 85 88 f2 ff ff 88 10 e9 90 0a 37 00 0f b6 05 90 01 04 8b 0d 90 01 04 03 8d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}