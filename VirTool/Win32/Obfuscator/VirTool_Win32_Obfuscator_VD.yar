
rule VirTool_Win32_Obfuscator_VD{
	meta:
		description = "VirTool:Win32/Obfuscator.VD,SIGNATURE_TYPE_PEHSTR_EXT,64 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_13_0 = {0f 68 19 2b 90 90 95 ff 75 e0 e8 90 01 02 ff ff ff 90 00 0a } //00 26 
		$a_68_1 = {80 ac c8 ff 75 e0 e8 90 01 02 ff ff 59 59 8b 4d d8 89 41 } //0c 68 
		$a_70_2 = {3a ff 75 e0 e8 90 01 02 ff ff 90 00 00 00 5d 04 00 00 1e 95 02 80 5c 1e 00 00 1f 95 02 80 00 00 01 00 27 00 08 00 c8 21 42 61 66 69 2e 43 00 00 01 40 05 82 5f 00 04 00 61 67 00 00 0a 00 09 00 05 00 00 06 00 14 66 00 69 00 64 00 75 00 63 00 69 00 61 00 2e 00 64 00 65 00 01 00 12 5f 00 } //69 00 
	condition:
		any of ($a_*)
 
}