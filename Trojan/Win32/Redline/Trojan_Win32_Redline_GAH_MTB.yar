
rule Trojan_Win32_Redline_GAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e6 89 c8 29 d0 d1 e8 01 c2 89 c8 c1 ea 90 01 01 6b d2 90 01 01 29 d0 c1 e8 90 01 01 0f b6 80 90 01 04 f7 d8 c1 e0 04 30 81 90 01 04 83 c1 01 81 f9 90 01 04 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}