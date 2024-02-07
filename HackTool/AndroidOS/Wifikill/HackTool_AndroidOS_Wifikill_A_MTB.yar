
rule HackTool_AndroidOS_Wifikill_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Wifikill.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 61 70 20 75 6e 61 62 6c 65 20 74 6f 20 72 65 61 64 20 73 74 75 66 66 73 } //01 00  Crap unable to read stuffs
		$a_00_1 = {53 65 72 76 69 63 65 20 63 72 61 73 68 65 64 2e 2e 2e 20 64 69 65 64 2e 2e 2e 20 76 61 70 6f 72 69 7a 65 64 2e 2e 2e 20 6d 79 20 62 61 64 } //01 00  Service crashed... died... vaporized... my bad
		$a_00_2 = {57 69 46 69 4b 69 6c 6c 20 73 65 72 76 69 63 65 } //01 00  WiFiKill service
		$a_00_3 = {4b 69 6c 6c 69 6e 67 3a } //01 00  Killing:
		$a_00_4 = {70 61 72 61 6e 6f 69 64 2e 6d 65 } //01 00  paranoid.me
		$a_00_5 = {68 61 63 6b } //00 00  hack
		$a_00_6 = {5d 04 00 00 } //65 98 
	condition:
		any of ($a_*)
 
}