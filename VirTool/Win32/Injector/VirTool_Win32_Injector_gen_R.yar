
rule VirTool_Win32_Injector_gen_R{
	meta:
		description = "VirTool:Win32/Injector.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 45 08 03 85 fc fb ff ff 8a 10 32 94 8d 00 fc ff ff 8b 45 08 03 85 fc fb ff ff 88 10 } //01 00 
		$a_01_1 = {68 9a 02 00 00 6a 00 ff 15 } //01 00 
		$a_01_2 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}