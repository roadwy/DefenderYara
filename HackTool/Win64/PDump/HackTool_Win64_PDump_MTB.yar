
rule HackTool_Win64_PDump_MTB{
	meta:
		description = "HackTool:Win64/PDump!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 47 4c 4f 42 41 4c 3f 3f 5c 4b 6e 6f 77 6e 44 6c 6c 73 } //\GLOBAL??\KnownDlls  01 00 
		$a_80_1 = {5c 3f 3f 5c 47 4c 4f 42 41 4c 52 4f 4f 54 } //\??\GLOBALROOT  01 00 
		$a_80_2 = {45 76 65 6e 74 41 67 67 72 65 67 61 74 69 6f 6e 2e 64 6c 6c } //EventAggregation.dll  01 00 
		$a_80_3 = {53 73 70 69 43 6c 69 2e 64 6c 6c } //SspiCli.dll  01 00 
		$a_80_4 = {53 2d 31 2d 35 2d 31 38 } //S-1-5-18  01 00 
		$a_80_5 = {53 2d 31 2d 35 2d 31 39 } //S-1-5-19  01 00 
		$a_00_6 = {44 65 66 69 6e 65 44 6f 73 44 65 76 69 63 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}