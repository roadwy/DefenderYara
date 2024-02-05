
rule VirTool_Win32_DelfInject_gen_CI{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 53 18 81 bd 90 01 04 50 45 00 00 90 00 } //01 00 
		$a_01_1 = {b9 42 4b 52 94 8b d3 } //01 00 
		$a_01_2 = {ff d5 50 ff 54 24 0c 83 c4 0c 5d 5f 5e 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}