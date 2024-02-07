
rule Trojan_BAT_Remcos_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {35 32 64 35 35 65 32 64 2d 32 33 38 31 2d 34 39 35 32 2d 62 34 33 62 2d 64 64 30 63 32 35 64 65 66 66 32 38 } //02 00  52d55e2d-2381-4952-b43b-dd0c25deff28
		$a_01_1 = {77 61 72 2e 70 64 62 } //02 00  war.pdb
		$a_01_2 = {79 50 6d 68 75 58 50 76 76 46 } //00 00  yPmhuXPvvF
	condition:
		any of ($a_*)
 
}