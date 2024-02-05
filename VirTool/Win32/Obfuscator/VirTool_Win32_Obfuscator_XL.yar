
rule VirTool_Win32_Obfuscator_XL{
	meta:
		description = "VirTool:Win32/Obfuscator.XL,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ff 8d 44 3d 90 01 01 0f b6 18 33 d9 03 da 47 88 18 83 ff 90 01 01 72 ed 33 ff 90 00 } //01 00 
		$a_02_1 = {c1 e7 06 03 c7 eb 0a 80 f1 90 01 01 80 c1 90 01 01 88 08 40 42 8a 0a 80 f9 90 01 01 75 ef c6 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}