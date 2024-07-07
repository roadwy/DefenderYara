
rule VirTool_Win32_Obfuscator_R{
	meta:
		description = "VirTool:Win32/Obfuscator.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 6a 00 6a 00 68 ff ff fb ff ff 15 90 01 04 85 c0 7e 08 6a 00 90 03 04 05 e8 90 01 05 ff 15 90 01 04 a1 90 01 04 31 05 90 01 04 31 05 90 01 04 33 c9 39 0d 90 01 04 76 18 a1 90 01 04 8a 15 90 01 04 03 c1 30 10 41 3b 0d 90 01 04 72 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}