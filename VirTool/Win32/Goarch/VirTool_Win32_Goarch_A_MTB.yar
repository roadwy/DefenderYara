
rule VirTool_Win32_Goarch_A_MTB{
	meta:
		description = "VirTool:Win32/Goarch.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 73 68 65 6c 6c 63 6f 64 65 2f 73 68 65 6c 6c 63 6f 64 65 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_1 = {48 8b 89 00 00 00 00 48 3b 61 10 0f 86 98 01 00 00 48 83 ec 70 48 89 6c 24 68 48 8d 6c 24 68 48 8d 05 49 04 04 00 48 89 44 24 50 48 8d 05 f5 30 01 00 48 89 04 24 } //00 00 
	condition:
		any of ($a_*)
 
}