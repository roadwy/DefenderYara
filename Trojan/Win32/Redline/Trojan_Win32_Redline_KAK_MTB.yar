
rule Trojan_Win32_Redline_KAK_MTB{
	meta:
		description = "Trojan:Win32/Redline.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d3 89 54 24 90 01 01 e8 90 01 04 81 3d 90 01 08 89 44 24 90 01 01 75 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 8b 44 24 90 01 01 33 44 24 90 01 01 8b c8 89 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 8d 44 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //01 00 
		$a_03_1 = {51 c7 04 24 90 01 04 8b 44 24 90 01 01 01 04 24 8b 04 24 31 44 24 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}