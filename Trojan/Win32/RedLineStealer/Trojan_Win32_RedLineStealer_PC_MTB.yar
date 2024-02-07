
rule Trojan_Win32_RedLineStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc 90 01 04 8b 45 0c 01 45 fc 83 6d fc 90 01 01 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_PC_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //03 00  VirtualProtect
		$a_03_2 = {b8 d5 41 1d d4 8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 90 01 01 2b c8 8a 81 90 01 04 30 04 1e 46 3b f7 72 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 c4 
	condition:
		any of ($a_*)
 
}