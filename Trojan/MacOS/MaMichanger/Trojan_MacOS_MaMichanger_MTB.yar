
rule Trojan_MacOS_MaMichanger_MTB{
	meta:
		description = "Trojan:MacOS/MaMichanger!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6c 6f 61 64 4d 61 4d 69 41 74 50 61 74 68 } //01 00  loadMaMiAtPath
		$a_00_1 = {72 65 6c 61 75 6e 63 68 57 69 74 68 50 72 69 76 69 6c 65 67 65 73 41 6e 64 50 61 72 61 6d 73 } //01 00  relaunchWithPrivilegesAndParams
		$a_00_2 = {6d 61 6d 69 5f 61 63 74 69 76 69 74 79 } //01 00  mami_activity
		$a_00_3 = {6d 61 63 75 70 5f 61 63 74 69 76 69 74 79 } //01 00  macup_activity
		$a_00_4 = {73 65 74 50 72 69 76 69 6c 61 67 65 73 54 6f 46 69 6c 65 } //01 00  setPrivilagesToFile
		$a_00_5 = {53 6c 79 42 6f 6f 74 73 43 6f 72 65 } //00 00  SlyBootsCore
	condition:
		any of ($a_*)
 
}