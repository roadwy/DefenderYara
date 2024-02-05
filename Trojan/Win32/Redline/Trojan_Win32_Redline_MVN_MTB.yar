
rule Trojan_Win32_Redline_MVN_MTB{
	meta:
		description = "Trojan:Win32/Redline.MVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8b 4d 90 01 01 d3 e0 89 75 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 00 } //01 00 
		$a_03_1 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 81 45 90 01 05 31 45 90 01 01 2b 5d 90 01 01 ff 4d 90 01 01 89 35 90 01 04 89 5d 90 01 01 0f 85 b5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}