
rule Trojan_Win32_Redline_GBH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 3e 8b c6 83 e0 03 8a 80 90 01 04 32 c3 02 c3 88 04 3e 0f b6 c3 50 50 68 90 01 04 e8 90 01 04 28 1c 3e 83 c4 90 01 01 46 3b 74 24 90 01 01 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}