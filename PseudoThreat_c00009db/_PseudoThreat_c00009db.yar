
rule _PseudoThreat_c00009db{
	meta:
		description = "!PseudoThreat_c00009db,SIGNATURE_TYPE_PEHSTR_EXT,46 00 44 00 0d 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7b 41 42 43 44 45 43 46 30 2d 34 42 31 35 2d 31 31 44 31 2d 41 42 45 44 2d 37 30 39 35 34 39 43 31 30 30 30 30 7d } //0a 00  {ABCDECF0-4B15-11D1-ABED-709549C10000}
		$a_01_1 = {7b 33 39 33 39 32 31 2d 65 39 33 39 33 39 31 2d 33 39 31 39 31 33 39 2d 33 64 33 61 37 33 38 2d 31 31 7d } //0a 00  {393921-e939391-3919139-3d3a738-11}
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //0a 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_01_3 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //0a 00  DisableRegistryTools
		$a_01_4 = {45 6e 61 62 6c 65 42 61 6c 6c 6f 6f 6e 54 69 70 73 } //05 00  EnableBalloonTips
		$a_00_5 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //03 00  \drivers\etc\hosts
		$a_01_6 = {77 69 6e 64 6f 77 73 75 70 64 61 74 65 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //03 00  windowsupdate.microsoft.com
		$a_01_7 = {6b 61 73 70 65 72 73 6b 79 2e 63 6f 6d } //03 00  kaspersky.com
		$a_01_8 = {6d 63 61 66 65 65 2e 63 6f 6d } //03 00  mcafee.com
		$a_01_9 = {73 79 6d 61 6e 74 65 63 2e 63 6f 6d } //01 00  symantec.com
		$a_01_10 = {31 39 32 2e 31 36 38 2e 32 30 30 2e 33 } //01 00  192.168.200.3
		$a_01_11 = {57 61 72 6e 69 6e 67 21 20 50 6f 74 65 6e 74 69 61 6c 20 53 70 79 77 61 72 65 20 4f 70 65 72 61 74 69 6f 6e 21 } //01 00  Warning! Potential Spyware Operation!
		$a_01_12 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6d 61 6b 69 6e 67 20 75 6e 61 75 74 68 6f 72 69 7a 65 64 20 63 6f 70 69 65 73 20 6f 66 20 79 6f 75 72 20 73 79 73 74 65 6d 20 61 6e 64 } //00 00  Your computer is making unauthorized copies of your system and
	condition:
		any of ($a_*)
 
}