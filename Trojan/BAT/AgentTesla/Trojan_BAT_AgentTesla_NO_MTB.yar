
rule Trojan_BAT_AgentTesla_NO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 65 74 5f 53 65 6c 65 63 74 43 6f 6d 6d 61 6e 64 } //01 00  set_SelectCommand
		$a_81_1 = {4d 48 4d 53 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  MHMS.Form1.resources
		$a_81_2 = {4d 48 4d 53 2e 66 72 6d 53 79 73 74 65 6d 49 6e 66 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  MHMS.frmSystemInfo.resources
		$a_81_3 = {24 32 34 30 62 66 30 32 31 2d 31 38 33 66 2d 34 36 66 36 2d 39 37 63 30 2d 63 64 34 39 31 38 61 33 34 38 65 39 } //01 00  $240bf021-183f-46f6-97c0-cd4918a348e9
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}