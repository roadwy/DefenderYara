
rule Trojan_Win32_PovertyStealer_RDA_MTB{
	meta:
		description = "Trojan:Win32/PovertyStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6f 76 65 72 74 79 20 69 73 20 74 68 65 20 70 61 72 65 6e 74 20 6f 66 20 63 72 69 6d 65 2e } //01 00  Poverty is the parent of crime.
		$a_01_1 = {2d 20 4f 70 65 72 61 74 69 6f 6e 53 79 73 74 65 6d 3a 20 25 64 3a 25 64 3a 25 64 } //01 00  - OperationSystem: %d:%d:%d
		$a_01_2 = {2d 20 48 57 49 44 3a 20 25 73 } //01 00  - HWID: %s
		$a_01_3 = {2d 20 53 63 72 65 65 6e 53 69 7a 65 3a 20 7b 6c 57 69 64 74 68 3d 25 64 2c 20 6c 48 65 69 67 68 74 3d 25 64 7d } //00 00  - ScreenSize: {lWidth=%d, lHeight=%d}
	condition:
		any of ($a_*)
 
}