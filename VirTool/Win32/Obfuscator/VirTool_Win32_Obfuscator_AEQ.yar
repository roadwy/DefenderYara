
rule VirTool_Win32_Obfuscator_AEQ{
	meta:
		description = "VirTool:Win32/Obfuscator.AEQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 90 01 04 c7 44 24 04 90 01 04 c7 04 24 90 01 01 ff ff ff e8 90 01 04 83 ec 10 4b 75 d1 31 c0 80 80 90 01 04 48 40 3d 90 01 01 06 00 00 75 f1 c7 05 90 01 08 a1 90 01 04 ff d0 90 09 0a 00 bb 90 01 04 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}