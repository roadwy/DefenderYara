
rule VirTool_Win32_Obfuscator_CX{
	meta:
		description = "VirTool:Win32/Obfuscator.CX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b3 02 41 b0 10 e8 90 01 01 00 00 00 10 c0 0f 83 f3 ff ff ff 0f 85 90 01 01 00 00 00 aa e9 90 01 01 ff ff ff e8 90 01 01 00 00 00 29 d9 0f 85 90 01 01 00 00 00 e8 90 01 01 00 00 00 e9 90 16 90 02 20 9c 90 02 10 9d 90 02 10 9c 90 02 10 9d 90 02 10 9c 90 02 10 9d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}