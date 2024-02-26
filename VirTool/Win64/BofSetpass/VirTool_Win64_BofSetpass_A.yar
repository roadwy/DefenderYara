
rule VirTool_Win64_BofSetpass_A{
	meta:
		description = "VirTool:Win64/BofSetpass.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 61 62 6c 65 20 74 6f 20 73 65 74 20 75 73 65 72 20 70 61 73 73 77 6f 72 64 } //01 00  Unable to set user password
		$a_01_1 = {55 73 65 72 20 70 61 73 73 77 6f 72 64 20 73 68 6f 75 6c 64 20 68 61 76 65 20 62 65 65 6e 20 73 65 74 } //01 00  User password should have been set
		$a_01_2 = {53 65 74 74 69 6e 67 20 70 61 73 73 77 6f 72 64 } //01 00  Setting password
		$a_01_3 = {73 65 74 75 73 65 72 70 61 73 73 20 66 61 69 6c 65 64 } //00 00  setuserpass failed
	condition:
		any of ($a_*)
 
}