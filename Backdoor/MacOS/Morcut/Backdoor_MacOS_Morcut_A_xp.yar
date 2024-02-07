
rule Backdoor_MacOS_Morcut_A_xp{
	meta:
		description = "Backdoor:MacOS/Morcut.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {6d 61 6b 65 42 61 63 6b 64 6f 6f 72 52 65 73 69 64 65 6e 74 } //01 00  makeBackdoorResident
		$a_00_1 = {2f 74 6d 70 2f 34 33 74 38 38 30 33 7a 7a 25 2e 38 64 2e 58 58 58 58 } //01 00  /tmp/43t8803zz%.8d.XXXX
		$a_00_2 = {61 64 64 42 61 63 6b 64 6f 6f 72 54 6f 53 4c 49 50 6c 69 73 74 } //01 00  addBackdoorToSLIPlist
		$a_00_3 = {69 73 42 61 63 6b 64 6f 6f 72 50 72 65 73 65 6e 74 49 6e 53 4c 49 3a } //01 00  isBackdoorPresentInSLI:
		$a_00_4 = {73 74 61 72 74 41 67 65 6e 74 73 } //01 00  startAgents
		$a_00_5 = {65 76 65 6e 74 73 4d 6f 6e 69 74 6f 72 } //01 00  eventsMonitor
		$a_00_6 = {69 6e 6a 65 63 74 42 75 6e 64 6c 65 } //00 00  injectBundle
		$a_00_7 = {5d 04 00 } //00 67 
	condition:
		any of ($a_*)
 
}