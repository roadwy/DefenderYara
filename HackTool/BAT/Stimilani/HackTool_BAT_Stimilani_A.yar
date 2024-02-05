
rule HackTool_BAT_Stimilani_A{
	meta:
		description = "HackTool:BAT/Stimilani.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 72 61 64 65 6f 66 66 65 72 2f 6e 65 77 2f 73 65 6e 64 } //tradeoffer/new/send  01 00 
		$a_80_1 = {73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d } //steamcommunity.com  01 00 
		$a_80_2 = {73 74 65 61 6d 4c 6f 67 69 6e } //steamLogin  01 00 
		$a_80_3 = {72 67 49 6e 76 65 6e 74 6f 72 79 } //rgInventory  01 00 
		$a_80_4 = {6a 73 6f 6e 5f 74 72 61 64 65 6f 66 66 65 72 } //json_tradeoffer  01 00 
		$a_80_5 = {53 54 41 54 55 53 20 49 53 20 55 4e 4b 4e 4f 57 4e 20 2d 20 54 48 49 53 20 53 48 4f 55 4c 44 20 4e 45 56 45 52 20 48 41 50 50 45 4e 21 } //STATUS IS UNKNOWN - THIS SHOULD NEVER HAPPEN!  00 00 
		$a_00_6 = {5d 04 00 00 } //5f 3f 
	condition:
		any of ($a_*)
 
}