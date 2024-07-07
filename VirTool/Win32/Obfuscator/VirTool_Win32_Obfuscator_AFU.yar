
rule VirTool_Win32_Obfuscator_AFU{
	meta:
		description = "VirTool:Win32/Obfuscator.AFU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 89 45 f8 c6 06 59 c6 46 01 2a c6 46 02 38 33 c0 40 8b 17 03 d0 83 c2 02 8b 1f 03 d8 4b 8a 1b 3a 1e 75 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}