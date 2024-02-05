
rule TrojanDropper_Win32_Cutwail_gen_E{
	meta:
		description = "TrojanDropper:Win32/Cutwail.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 06 74 c6 46 01 63 c6 46 02 70 c6 46 03 73 c6 46 04 72 c6 46 05 00 } //01 00 
		$a_01_1 = {68 00 24 6c 9d ff 74 24 24 89 44 24 24 89 7c 24 20 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}