
rule VirTool_Win32_Tacko_A_MTB{
	meta:
		description = "VirTool:Win32/Tacko.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 63 6f 73 2f 70 6b 67 2f 74 61 63 6f 73 2e 52 65 76 65 72 73 65 53 68 65 6c 6c } //01 00 
		$a_01_1 = {74 61 63 6f 73 2f 70 6b 67 2f 74 61 63 6f 73 2e 2e 69 6e 69 74 74 61 73 6b } //01 00 
		$a_01_2 = {74 61 63 6f 73 2f 74 61 63 6f 73 5f 77 69 6e 64 6f 77 73 2e 67 6f } //01 00 
		$a_01_3 = {63 6d 64 2f 74 61 63 6f 73 2f 74 61 63 6f 73 2e 67 6f } //00 00 
	condition:
		any of ($a_*)
 
}