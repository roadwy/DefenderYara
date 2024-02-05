
rule VirTool_Win32_Obfuscator_CAL{
	meta:
		description = "VirTool:Win32/Obfuscator.CAL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 44 24 30 6b c6 44 24 35 6c c6 44 24 36 33 c6 44 24 37 32 88 5c 24 38 } //01 00 
		$a_03_1 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 90 01 04 30 04 39 41 3b ce 72 df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}