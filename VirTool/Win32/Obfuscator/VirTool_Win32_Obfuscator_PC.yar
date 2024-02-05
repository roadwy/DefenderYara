
rule VirTool_Win32_Obfuscator_PC{
	meta:
		description = "VirTool:Win32/Obfuscator.PC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 23 f2 8b 4c b0 08 03 f9 23 fa 89 7d 08 8b 7c b8 08 8b 5d 08 89 7c b0 08 03 f9 23 fa 89 4c 98 08 8a 4c b8 08 8b 7d fc 32 0f 8b 5d f8 88 0c 3b 47 3b 7d f4 89 7d fc 8b 7d 08 75 c4 } //00 00 
	condition:
		any of ($a_*)
 
}