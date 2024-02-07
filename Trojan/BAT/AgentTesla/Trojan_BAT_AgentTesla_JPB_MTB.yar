
rule Trojan_BAT_AgentTesla_JPB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 6f 90 01 03 0a 00 00 09 17 58 0d 09 06 6f 90 01 03 0a 18 5b fe 04 13 04 11 04 90 00 } //0a 00 
		$a_81_1 = {24 62 62 32 66 39 35 61 39 2d 65 62 39 66 2d 34 33 66 66 2d 39 32 31 31 2d 62 34 34 64 66 64 30 65 34 33 35 62 } //01 00  $bb2f95a9-eb9f-43ff-9211-b44dfd0e435b
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_4 = {50 00 61 00 6e 00 61 00 6d 00 65 00 72 00 61 00 2e 00 50 00 6f 00 72 00 73 00 63 00 68 } //00 00 
	condition:
		any of ($a_*)
 
}