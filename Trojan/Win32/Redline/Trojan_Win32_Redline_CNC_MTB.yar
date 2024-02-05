
rule Trojan_Win32_Redline_CNC_MTB{
	meta:
		description = "Trojan:Win32/Redline.CNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 f8 8b 4d d4 03 cb 33 c8 89 45 0c 89 4d ec 89 35 90 01 04 8b 45 90 01 01 01 05 90 00 } //01 00 
		$a_03_1 = {c1 e8 05 03 45 e0 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 89 75 90 01 01 8b 45 90 01 01 01 45 90 01 01 2b 7d 90 01 01 ff 4d 90 01 01 8b 4d 90 01 01 89 7d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}