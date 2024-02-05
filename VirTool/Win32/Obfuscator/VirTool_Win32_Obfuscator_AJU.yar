
rule VirTool_Win32_Obfuscator_AJU{
	meta:
		description = "VirTool:Win32/Obfuscator.AJU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 8d 7c 3d 90 01 01 8a 17 80 f2 90 01 01 80 ea 90 01 01 88 17 8b 55 90 01 01 8b 7d 90 01 01 80 f2 90 01 01 80 ea 90 01 01 02 c2 3c 08 72 dd 90 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}