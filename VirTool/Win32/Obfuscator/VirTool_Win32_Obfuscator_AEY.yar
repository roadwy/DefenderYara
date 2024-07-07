
rule VirTool_Win32_Obfuscator_AEY{
	meta:
		description = "VirTool:Win32/Obfuscator.AEY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 85 04 00 00 03 4d 0c 81 e1 4e 61 bc 00 89 0d e0 7f 40 00 83 2d fd ad 40 00 01 0f 83 70 ff ff ff bb 08 43 00 00 2b 5d 14 89 1d f8 92 40 00 bb 0f 20 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}