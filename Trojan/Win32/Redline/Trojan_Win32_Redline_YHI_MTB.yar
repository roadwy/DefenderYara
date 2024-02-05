
rule Trojan_Win32_Redline_YHI_MTB{
	meta:
		description = "Trojan:Win32/Redline.YHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 03 4c 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 6a 90 01 01 6a 90 01 01 8d 54 24 90 01 01 52 ff 15 90 01 04 8b 4c 24 90 01 01 33 4c 24 90 01 01 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 83 6c 24 90 01 02 8b 4c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}