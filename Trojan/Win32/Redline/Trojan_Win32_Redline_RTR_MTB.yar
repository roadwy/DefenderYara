
rule Trojan_Win32_Redline_RTR_MTB{
	meta:
		description = "Trojan:Win32/Redline.RTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 03 45 90 01 01 89 4d 90 01 01 33 d0 33 d1 52 8d 45 f8 50 e8 90 01 04 8b 75 f8 c1 e6 04 81 3d 90 01 08 75 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 03 45 90 01 01 03 f2 33 c6 33 45 fc c7 05 90 01 08 89 45 f4 8b 45 f4 29 45 08 83 65 0c 90 01 01 8b 45 90 01 01 01 45 90 01 01 2b 7d 0c ff 4d 90 01 01 8b 45 90 01 01 89 7d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}