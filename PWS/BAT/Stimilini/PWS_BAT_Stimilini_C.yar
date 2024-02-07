
rule PWS_BAT_Stimilini_C{
	meta:
		description = "PWS:BAT/Stimilini.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 67 65 74 5f 75 6d 71 75 69 64 00 } //01 00  最瑥畟煭極d
		$a_01_1 = {00 73 65 74 5f 75 6d 71 75 69 64 00 } //01 00  猀瑥畟煭極d
		$a_01_2 = {00 67 65 74 5f 73 74 65 61 6d 49 44 00 } //00 00 
		$a_01_3 = {00 61 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_BAT_Stimilini_C_2{
	meta:
		description = "PWS:BAT/Stimilini.C,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 73 74 65 61 6d 49 44 } //01 00  get_steamID
		$a_01_1 = {67 65 74 5f 66 72 69 65 6e 64 73 43 6f 75 6e 74 } //01 00  get_friendsCount
		$a_01_2 = {67 65 74 5f 75 6e 69 78 74 69 6d 65 73 74 61 6d 70 } //01 00  get_unixtimestamp
		$a_01_3 = {73 65 74 5f 73 65 73 73 69 6f 6e 49 44 } //01 00  set_sessionID
		$a_01_4 = {73 65 74 5f 75 6d 71 75 69 64 } //01 00  set_umquid
		$a_01_5 = {67 65 74 5f 61 63 63 65 73 73 5f 74 6f 6b 65 6e } //00 00  get_access_token
		$a_01_6 = {00 67 16 00 00 ae c8 62 } //02 1c 
	condition:
		any of ($a_*)
 
}