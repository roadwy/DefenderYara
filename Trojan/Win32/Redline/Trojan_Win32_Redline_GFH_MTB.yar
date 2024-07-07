
rule Trojan_Win32_Redline_GFH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 80 90 01 04 32 04 33 0f b6 0c 33 8d 14 08 88 14 33 2a d1 88 14 33 46 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}