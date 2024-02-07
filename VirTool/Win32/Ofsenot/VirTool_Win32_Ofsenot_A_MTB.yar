
rule VirTool_Win32_Ofsenot_A_MTB{
	meta:
		description = "VirTool:Win32/Ofsenot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 72 63 2f 6e 6f 74 69 6f 6e 2e 72 73 } //01 00  src/notion.rs
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 6e 6f 74 69 6f 6e 2e 63 6f 6d 2f 76 31 } //01 00  https://api.notion.com/v1
		$a_01_2 = {61 64 6d 69 6e 73 72 63 2f 63 6d 64 2f 65 6c 65 76 61 74 65 2e 72 73 } //01 00  adminsrc/cmd/elevate.rs
		$a_01_3 = {73 72 63 2f 63 6d 64 2f 67 65 74 70 72 69 76 73 2e 72 73 } //01 00  src/cmd/getprivs.rs
		$a_01_4 = {73 72 63 2f 63 6d 64 2f 69 6e 6a 65 63 74 2e 72 73 } //00 00  src/cmd/inject.rs
	condition:
		any of ($a_*)
 
}