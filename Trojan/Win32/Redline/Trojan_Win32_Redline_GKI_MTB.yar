
rule Trojan_Win32_Redline_GKI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 c7 33 c1 2b f0 89 44 24 90 01 01 8b c6 c1 e0 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b ce c1 e9 90 01 01 8d 3c 33 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}