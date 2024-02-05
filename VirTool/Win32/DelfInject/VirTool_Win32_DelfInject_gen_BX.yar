
rule VirTool_Win32_DelfInject_gen_BX{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BX,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {58 75 52 75 6e 50 45 } //04 00 
		$a_01_1 = {52 65 61 65 50 72 6e 63 64 72 73 4d 64 6d 6f 73 79 } //04 00 
		$a_01_2 = {6e 6f 69 74 63 65 53 66 4f 77 65 69 56 70 61 6d 6e 55 74 4e } //00 00 
	condition:
		any of ($a_*)
 
}