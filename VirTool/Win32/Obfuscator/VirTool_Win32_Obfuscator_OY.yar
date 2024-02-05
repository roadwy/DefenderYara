
rule VirTool_Win32_Obfuscator_OY{
	meta:
		description = "VirTool:Win32/Obfuscator.OY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5a 31 c2 83 ea ff 59 90 17 02 03 03 5b 5f 5e 5e 5f 5b 29 d4 89 f2 89 fe 87 f2 51 56 29 90 01 01 89 90 01 01 f4 89 90 01 02 55 90 00 } //01 00 
		$a_03_1 = {c7 45 a4 00 00 00 00 8d 90 01 01 a4 6a 00 ff 15 90 01 03 00 35 00 40 0f 00 3d 02 40 0f c0 74 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}