
rule Trojan_Win32_Redline_GMA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 06 83 c4 90 01 01 0f b6 0f 03 c8 0f b6 c1 8b 8d 90 01 04 8a 84 05 90 01 04 30 81 90 01 04 41 89 8d 90 01 04 81 f9 90 01 04 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}