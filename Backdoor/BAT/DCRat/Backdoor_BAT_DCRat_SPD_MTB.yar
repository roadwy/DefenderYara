
rule Backdoor_BAT_DCRat_SPD_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 04 18 9a 28 90 01 03 0a 0c 11 04 8e 69 1a 32 0a 11 04 19 9a 28 90 01 03 0a 0d 02 7c 58 00 00 04 90 00 } //01 00 
		$a_01_1 = {42 00 75 00 69 00 6c 00 64 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 54 00 77 00 65 00 61 00 6b 00 73 00 50 00 6c 00 75 00 67 00 69 00 6e 00 2e 00 64 00 6c 00 6c 00 } //00 00  BuildInstallationTweaksPlugin.dll
	condition:
		any of ($a_*)
 
}