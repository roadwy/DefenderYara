
rule VirTool_Win32_Bofenableuser_A{
	meta:
		description = "VirTool:Win32/Bofenableuser.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 75 65 73 74 } //01 00  Guest
		$a_01_1 = {41 63 63 6f 75 6e 74 20 77 61 73 20 64 69 73 61 62 6c 65 64 2c 20 61 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 65 6e 61 62 6c 65 } //01 00  Account was disabled, attempting to enable
		$a_01_2 = {41 63 63 6f 75 6e 74 20 73 68 6f 75 6c 64 20 62 65 20 65 6e 61 62 6c 65 64 } //01 00  Account should be enabled
		$a_01_3 = {45 6e 61 62 6c 65 55 73 65 72 20 66 61 69 6c 65 64 } //01 00  EnableUser failed
		$a_01_4 = {62 6f 66 73 74 6f 70 } //00 00  bofstop
	condition:
		any of ($a_*)
 
}