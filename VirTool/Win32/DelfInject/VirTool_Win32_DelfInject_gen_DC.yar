
rule VirTool_Win32_DelfInject_gen_DC{
	meta:
		description = "VirTool:Win32/DelfInject.gen!DC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 83 ef 1a 29 ff b8 2e 00 00 00 31 c0 4a 0f 85 0d fe ff ff 68 00 01 00 00 8d 85 f7 fd ff ff 50 6a 00 e8 90 01 02 ff ff 83 c0 10 83 f8 20 7f 09 6a 00 6a ff e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}