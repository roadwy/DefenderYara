
rule VirTool_Win32_DelfInject_gen_BP{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 3a 47 4b 0f 85 90 01 04 8b 45 fc e8 90 01 04 8b d8 4b 85 db 7c 29 90 00 } //01 00 
		$a_03_1 = {81 c7 f8 00 00 00 0f b7 9d 90 01 02 ff ff 4b 85 db 0f 8c 90 00 } //01 00 
		$a_01_2 = {8b 45 f0 03 85 d8 fe ff ff 89 85 18 fe ff ff } //01 00 
	condition:
		any of ($a_*)
 
}