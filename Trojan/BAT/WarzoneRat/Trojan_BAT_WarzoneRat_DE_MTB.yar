
rule Trojan_BAT_WarzoneRat_DE_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 38 39 33 31 63 32 63 62 2d 31 34 36 66 2d 34 32 64 61 2d 62 36 36 36 2d 66 62 37 31 62 66 61 30 34 66 65 63 } //01 00  $8931c2cb-146f-42da-b666-fb71bfa04fec
		$a_81_1 = {50 68 61 72 6d 61 63 79 2e 45 6e 74 65 72 70 72 69 73 65 53 65 72 76 69 63 65 73 48 65 6c 70 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Pharmacy.EnterpriseServicesHelper.resources
		$a_81_2 = {50 68 61 72 6d 61 63 79 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Pharmacy.My.Resources
		$a_81_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_4 = {42 68 61 72 61 74 20 42 69 6f 74 65 63 68 } //01 00  Bharat Biotech
		$a_81_5 = {67 65 74 5f 48 6f 74 54 72 61 63 6b } //01 00  get_HotTrack
		$a_81_6 = {4c 6f 61 64 48 69 6e 74 } //00 00  LoadHint
	condition:
		any of ($a_*)
 
}