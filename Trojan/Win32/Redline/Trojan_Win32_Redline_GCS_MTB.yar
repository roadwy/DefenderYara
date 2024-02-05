
rule Trojan_Win32_Redline_GCS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f bf 4c 24 4e 31 c8 66 89 84 24 90 01 04 8d 84 24 90 01 04 89 84 24 90 01 04 8b 84 24 90 01 04 0f b6 00 0f b6 8c 24 90 01 04 d3 f8 88 c1 8b 84 24 90 01 04 88 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}