
rule TrojanSpy_Win32_Cutwail_gen_E{
	meta:
		description = "TrojanSpy:Win32/Cutwail.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 0f 8b 44 24 18 c6 46 06 68 89 46 07 c6 46 0b c3 } //01 00 
		$a_01_1 = {8a 0c 32 3a cb 74 09 84 c9 74 05 32 cb 88 0c 32 42 3b d0 7c eb } //00 00 
	condition:
		any of ($a_*)
 
}