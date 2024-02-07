
rule TrojanDropper_Win32_Agent_UZ{
	meta:
		description = "TrojanDropper:Win32/Agent.UZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 33 33 32 32 2e 6f 72 67 } //01 00  .3322.org
		$a_00_1 = {44 4f 57 53 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 43 6f 6d 5c } //01 00  DOWS\\system32\\Com\
		$a_00_2 = {6f 70 65 6e 33 33 38 39 } //01 00  open3389
		$a_00_3 = {72 76 69 63 65 73 5c 70 6f 7a 69 61 69 6e 69 5c } //02 00  rvices\poziaini\
		$a_02_4 = {75 11 6a 00 6a 7b 68 00 01 00 00 53 e8 90 01 04 eb 0f 90 00 } //02 00 
		$a_02_5 = {68 c8 00 00 00 e8 90 01 04 e8 90 01 04 68 c8 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}