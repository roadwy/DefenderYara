
rule TrojanSpy_BAT_Yubaceds_A{
	meta:
		description = "TrojanSpy:BAT/Yubaceds.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 77 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 66 00 72 00 6f 00 6d 00 20 00 43 00 6c 00 69 00 6e 00 65 00 74 00 20 00 49 00 64 00 3a 00 } //01 00  New infection from Clinet Id:
		$a_00_1 = {49 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 66 00 72 00 6f 00 6d 00 20 00 43 00 6c 00 69 00 6e 00 65 00 74 00 20 00 49 00 64 00 3a 00 } //01 00  Infection logger from Clinet Id:
		$a_00_2 = {44 00 65 00 63 00 61 00 79 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 6f 00 61 00 64 00 65 00 64 00 20 00 41 00 74 00 } //01 00  Decay Public Logger Loaded At
		$a_01_3 = {64 65 63 61 79 5f 73 75 62 5f 70 72 6f 6a 65 63 74 2e } //00 00  decay_sub_project.
	condition:
		any of ($a_*)
 
}