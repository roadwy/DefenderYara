
rule VirTool_Win32_Obfuscator_CX{
	meta:
		description = "VirTool:Win32/Obfuscator.CX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b3 02 41 b0 10 e8 ?? 00 00 00 10 c0 0f 83 f3 ff ff ff 0f 85 ?? 00 00 00 aa e9 ?? ff ff ff e8 ?? 00 00 00 29 d9 0f 85 ?? 00 00 00 e8 ?? 00 00 00 e9 90 16 [0-20] 9c [0-10] 9d [0-10] 9c [0-10] 9d [0-10] 9c [0-10] 9d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}