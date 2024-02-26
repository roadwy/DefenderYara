
rule Trojan_BAT_Formbook_DR_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 32 31 34 65 33 62 66 33 2d 38 63 32 37 2d 34 34 66 63 2d 62 37 63 37 2d 36 30 66 61 36 33 31 63 37 66 66 64 } //01 00  $214e3bf3-8c27-44fc-b7c7-60fa631c7ffd
		$a_81_1 = {4c 4d 53 5f 67 75 69 2e 52 65 73 6f 75 72 63 65 73 } //01 00  LMS_gui.Resources
		$a_81_2 = {64 61 74 61 62 61 73 65 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //01 00  databaseConnectionString
		$a_81_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_81_4 = {41 75 74 6f 6d 61 74 69 6f 6e 4c 69 76 65 52 65 67 69 6f 6e } //01 00  AutomationLiveRegion
		$a_81_5 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}