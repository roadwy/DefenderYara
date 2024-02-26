
rule Trojan_BAT_LummaStealer_MA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 09 11 03 16 11 03 8e 69 28 90 01 03 06 13 06 20 0c 00 00 00 28 90 01 03 06 3a 35 fe ff ff 26 38 2b fe ff ff 02 1f 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LummaStealer_MA_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 bf b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 f0 01 00 00 ea 00 00 00 39 } //02 00 
		$a_01_1 = {36 35 37 37 33 39 32 38 2d 42 36 44 30 2d 32 41 35 37 2d 32 33 31 44 2d 42 30 37 37 37 41 36 32 37 41 32 43 } //02 00  65773928-B6D0-2A57-231D-B0777A627A2C
		$a_01_2 = {43 44 42 41 41 31 43 31 2d 36 38 41 39 2d 30 31 37 42 2d 43 34 31 44 2d 33 30 33 45 34 35 42 42 37 46 35 33 } //02 00  CDBAA1C1-68A9-017B-C41D-303E45BB7F53
		$a_01_3 = {65 72 72 6f 72 5f 63 6f 72 72 65 63 74 69 6f 6e 5f 75 70 64 61 74 65 5f 63 68 65 63 6b 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //02 00  error_correction_update_check.My.Resources
		$a_01_4 = {69 6e 73 74 61 6c 6c 61 74 69 6f 6e 5f 73 6f 6c 75 74 69 6f 6e 5f 66 6f 72 5f 75 73 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //00 00  installation_solution_for_use.My.Resources
	condition:
		any of ($a_*)
 
}