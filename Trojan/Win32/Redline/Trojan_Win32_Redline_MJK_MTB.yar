
rule Trojan_Win32_Redline_MJK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8d 0c 07 33 4d 0c 89 35 90 01 04 33 4d f4 89 4d f4 8b 45 f4 01 05 90 01 04 51 8d 45 f8 50 e8 90 01 04 8b 7d f8 c1 e7 04 81 3d 90 01 08 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}