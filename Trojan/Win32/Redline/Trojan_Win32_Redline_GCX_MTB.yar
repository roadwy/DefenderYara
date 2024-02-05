
rule Trojan_Win32_Redline_GCX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {80 c2 d1 d0 ca 80 c2 ad c0 c2 05 80 c2 5e 80 f2 7b 80 c2 3b 80 f2 44 00 ca 88 c5 30 d5 80 c5 67 88 6c 04 30 83 f8 2d 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GCX_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 4d bf 8b 45 c0 33 d2 be 90 01 04 f7 f6 0f b6 92 90 01 04 33 ca 88 4d c7 8b 45 c0 8a 88 90 01 04 88 4d be 0f b6 55 c7 8b 45 c0 0f b6 88 90 01 04 03 ca 8b 55 c0 88 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}