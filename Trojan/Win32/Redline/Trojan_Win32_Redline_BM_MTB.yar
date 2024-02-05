
rule Trojan_Win32_Redline_BM_MTB{
	meta:
		description = "Trojan:Win32/Redline.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 83 c2 01 89 55 f0 8b 45 f0 3b 05 90 01 04 73 22 0f b6 0d 90 01 04 8b 15 90 01 04 03 55 f0 0f b6 02 33 c1 8b 0d 90 01 04 03 4d f0 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}