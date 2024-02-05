
rule Trojan_Win32_Redline_GBJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b7 4c 24 14 80 05 90 01 04 83 2d 8d 6f 24 4f 33 c1 c7 05 90 01 04 02 00 00 00 89 35 90 01 04 89 15 90 01 04 66 89 44 24 14 39 35 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}