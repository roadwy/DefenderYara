
rule VirTool_Win32_Obfuscator_APF{
	meta:
		description = "VirTool:Win32/Obfuscator.APF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 08 58 69 c0 90 01 02 00 00 8b 4d 90 01 01 dd 05 90 01 02 40 00 dd 1c 01 6a 08 58 69 c0 90 01 02 00 00 8b 4d 90 01 01 dd 05 90 01 02 40 00 dd 1c 01 6a 08 58 69 c0 90 01 02 00 00 8b 4d 90 01 01 dd 05 90 01 02 40 00 dd 1c 01 6a 08 58 69 c0 90 01 02 00 00 8b 4d 90 01 01 dd 05 90 01 02 40 00 dd 1c 01 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}