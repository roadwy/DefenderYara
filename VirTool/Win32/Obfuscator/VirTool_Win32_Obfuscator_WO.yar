
rule VirTool_Win32_Obfuscator_WO{
	meta:
		description = "VirTool:Win32/Obfuscator.WO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 75 6e 00 90 01 08 33 31 34 32 90 00 } //01 00 
		$a_03_1 = {33 31 34 32 90 01 0c 52 75 6e 90 00 } //0a 00 
		$a_00_2 = {29 18 68 fc e3 fe f8 } //00 00 
	condition:
		any of ($a_*)
 
}