
rule Trojan_Win32_Redline_GKH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 94 05 90 01 04 01 c2 31 c2 80 c2 90 01 01 80 f2 90 01 01 0f b6 d2 01 c2 31 c2 80 f2 90 01 01 00 ca 30 c2 88 94 05 90 01 04 83 c0 90 01 01 80 c1 90 01 01 83 f8 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}