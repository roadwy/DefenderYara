
rule VirTool_Win32_Injector_gen_BU{
	meta:
		description = "VirTool:Win32/Injector.gen!BU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {5a 77 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00 e8 90 01 04 ff e0 e8 90 00 } //01 00 
		$a_03_1 = {5a 77 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 e8 90 01 04 ff e0 e8 90 00 } //01 00 
		$a_03_2 = {5a 77 52 65 73 75 6d 65 54 68 72 65 61 64 00 e8 90 01 04 ff e0 e8 90 00 } //01 00 
		$a_03_3 = {83 7d fc 02 74 08 83 7d fc 03 74 14 eb 17 8b 45 0c ff 30 8b 45 0c 8b 48 10 e8 90 01 04 eb 07 33 c0 40 eb 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}