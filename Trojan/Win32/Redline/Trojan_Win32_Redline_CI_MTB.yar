
rule Trojan_Win32_Redline_CI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b c6 ba 98 c7 44 00 83 e0 90 01 01 8b cf 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 04 50 e8 90 01 04 88 90 01 05 46 59 81 fe 90 01 04 72 90 00 } //05 00 
		$a_03_1 = {83 e9 06 8b c2 d3 e8 4d 24 90 01 01 0c 90 01 01 88 03 ff 06 8b 1e 85 ed 7f 90 00 } //01 00 
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //00 00  VirtualProtectEx
	condition:
		any of ($a_*)
 
}