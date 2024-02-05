
rule Trojan_Win32_Redline_GKM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 8d 90 01 04 8b 95 90 01 04 3b 15 90 01 04 73 90 01 01 0f b6 05 90 01 04 8b 0d 90 01 04 03 8d 90 01 04 0f b6 11 33 d0 a1 90 01 04 03 85 90 01 04 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}