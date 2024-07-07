
rule VirTool_Win32_Obfuscator_AOJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AOJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 b2 32 85 f6 74 0d 30 14 38 8d 0c 38 40 fe c2 3b c6 72 f3 81 fb ff ff 01 00 74 0b 43 81 fb 00 00 00 01 7c da eb 15 33 c9 b2 33 85 f6 74 0d 30 14 39 8d 04 39 41 fe c2 3b ce 72 f3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}