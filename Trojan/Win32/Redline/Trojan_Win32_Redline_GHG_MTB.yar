
rule Trojan_Win32_Redline_GHG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c 90 01 04 88 84 34 90 01 04 88 8c 3c 90 01 04 0f b6 84 34 90 01 04 03 c2 0f b6 c0 0f b6 84 04 90 01 04 30 83 90 01 04 43 81 fb 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}