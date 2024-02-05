
rule Trojan_Win32_Redline_WYK_MTB{
	meta:
		description = "Trojan:Win32/Redline.WYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 33 5d 90 01 01 31 5d 90 01 01 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 ec 89 35 90 01 04 33 d0 89 55 d8 8b 45 d8 29 45 f0 8b 45 d0 29 45 f4 ff 4d e0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}