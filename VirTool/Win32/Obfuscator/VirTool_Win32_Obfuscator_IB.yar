
rule VirTool_Win32_Obfuscator_IB{
	meta:
		description = "VirTool:Win32/Obfuscator.IB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 50 01 00 92 e8 1f 00 00 00 8b 54 24 0c 8b 82 b0 00 00 00 48 75 09 6a f5 59 29 8a b8 00 00 00 89 82 b0 00 00 00 33 c0 c3 33 c9 64 ff 31 64 89 21 29 05 00 10 40 00 83 c4 08 f4 c3 } //00 00 
	condition:
		any of ($a_*)
 
}