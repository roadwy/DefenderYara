
rule TrojanClicker_Win32_Agent_AN{
	meta:
		description = "TrojanClicker:Win32/Agent.AN,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 10 66 61 73 74 6e 73 90 02 04 2e 65 78 65 90 00 } //01 00 
		$a_00_1 = {73 65 61 72 63 68 2e 73 65 61 72 63 68 66 69 6e 64 65 72 2e 62 69 7a } //01 00  search.searchfinder.biz
		$a_00_2 = {62 65 73 74 66 69 6e 64 7a 6f 6e 65 2e 63 6f 6d 2f 73 65 61 72 63 68 2e 70 68 70 } //01 00  bestfindzone.com/search.php
		$a_00_3 = {62 72 6f 77 73 65 72 65 73 75 6c 74 73 2e 63 6f 6d } //01 00  browseresults.com
		$a_00_4 = {74 68 65 64 72 65 61 6d 73 65 61 72 63 68 2e 63 6f 6d } //00 00  thedreamsearch.com
	condition:
		any of ($a_*)
 
}