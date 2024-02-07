
rule Backdoor_Win32_Leeson_C_dha{
	meta:
		description = "Backdoor:Win32/Leeson.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 64 00 75 00 6c 00 74 00 2e 00 73 00 66 00 74 00 } //01 00  adult.sft
		$a_01_1 = {44 6f 77 6e 46 69 6c 65 20 53 75 63 63 65 73 73 } //01 00  DownFile Success
		$a_01_2 = {44 6f 77 6e 46 69 6c 65 20 46 61 69 6c 75 72 65 } //01 00  DownFile Failure
		$a_01_3 = {52 65 6d 6f 74 65 45 78 65 63 20 53 75 63 63 65 73 73 } //01 00  RemoteExec Success
		$a_01_4 = {26 73 74 72 69 6e 67 73 43 6f 6d 61 6e 64 3d } //01 00  &stringsComand=
		$a_01_5 = {26 73 74 72 69 6e 67 73 49 64 3d } //00 00  &stringsId=
	condition:
		any of ($a_*)
 
}