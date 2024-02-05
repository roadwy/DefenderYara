
rule Trojan_Win32_Bandit_DHB_MTB{
	meta:
		description = "Trojan:Win32/Bandit.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f7 2b ee 8b 44 24 90 01 01 d1 6c 24 90 01 01 29 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 01 04 81 3d 90 01 08 75 29 90 00 } //01 00 
		$a_02_1 = {8b f7 d3 e7 c1 ee 05 03 74 24 90 01 01 03 7c 24 90 01 01 33 f8 81 3d 90 01 08 75 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}