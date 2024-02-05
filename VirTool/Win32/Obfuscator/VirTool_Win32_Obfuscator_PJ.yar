
rule VirTool_Win32_Obfuscator_PJ{
	meta:
		description = "VirTool:Win32/Obfuscator.PJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 02 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 f1 02 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 00 00 00 } //01 00 
		$a_02_1 = {ff d0 ff 35 90 01 04 a1 90 01 04 68 90 01 04 68 90 01 04 05 c4 11 00 00 ff d0 a1 90 01 08 05 90 01 02 00 00 ff d0 90 02 20 68 90 01 04 ff 74 24 90 01 01 e8 90 01 01 00 00 00 90 01 01 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}