
rule VirTool_Win32_Obfuscator_GA{
	meta:
		description = "VirTool:Win32/Obfuscator.GA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 50 51 66 58 59 b0 90 01 01 b3 90 01 01 00 90 01 01 66 b8 90 01 02 b7 90 01 01 66 01 d8 b9 90 01 04 89 d0 e2 fc 90 00 } //01 00 
		$a_03_1 = {66 31 c0 30 c0 30 db 30 ff b9 90 01 04 e2 fe 31 c0 31 c9 31 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}