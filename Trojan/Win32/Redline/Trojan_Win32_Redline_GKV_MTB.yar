
rule Trojan_Win32_Redline_GKV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 11 6b c0 90 01 01 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 90 01 01 99 b9 90 01 04 f7 f9 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}