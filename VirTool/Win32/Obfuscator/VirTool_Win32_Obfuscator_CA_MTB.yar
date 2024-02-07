
rule VirTool_Win32_Obfuscator_CA_MTB{
	meta:
		description = "VirTool:Win32/Obfuscator.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 45 e8 68 90 01 03 00 50 c7 45 fc 00 00 00 00 c7 45 e8 44 00 00 00 e8 1a 09 00 00 8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 40 89 45 08 b8 90 01 03 00 c3 90 00 } //01 00 
		$a_01_1 = {53 74 61 72 74 41 73 46 72 61 6d 65 50 72 6f 63 65 73 73 } //00 00  StartAsFrameProcess
	condition:
		any of ($a_*)
 
}