
rule VirTool_Win32_Obfuscator_CAI{
	meta:
		description = "VirTool:Win32/Obfuscator.CAI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 9d 8b d8 8d 85 90 01 02 ff ff 90 90 50 33 db 3e ff 15 90 01 04 9c 58 90 90 8b d8 05 90 01 04 2d 46 02 00 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}