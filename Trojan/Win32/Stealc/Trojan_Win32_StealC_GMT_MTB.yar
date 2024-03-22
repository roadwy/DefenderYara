
rule Trojan_Win32_StealC_GMT_MTB{
	meta:
		description = "Trojan:Win32/StealC.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 3e 46 3b f3 7c f3 } //01 00 
		$a_03_1 = {8d 9b 00 00 00 00 a1 80 9c 83 00 89 44 24 90 01 01 b8 31 a2 00 00 01 44 24 90 01 01 8b 4c 24 10 8a 14 31 a1 0c 78 83 00 88 14 30 81 3d 90 01 04 ab 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}