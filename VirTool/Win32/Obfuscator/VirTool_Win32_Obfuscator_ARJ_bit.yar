
rule VirTool_Win32_Obfuscator_ARJ_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ARJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 90 01 01 ec 8b 4d 90 01 01 3b 4d 90 01 01 73 90 01 01 8b 55 90 01 01 03 55 90 01 01 33 c0 8a 02 05 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}