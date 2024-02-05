
rule VirTool_Win32_DelfInject_gen_W{
	meta:
		description = "VirTool:Win32/DelfInject.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 45 54 00 ff ff ff ff 02 00 00 00 43 46 00 } //01 00 
		$a_02_1 = {8d 45 fc e8 90 01 04 8b 55 fc 0f b6 54 32 ff 90 03 01 01 33 32 d3 88 54 30 ff 43 46 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}