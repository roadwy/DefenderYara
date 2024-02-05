
rule VirTool_Win32_Obfuscator_ZJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ZJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 83 c0 13 28 10 c1 c2 07 69 d2 01 00 01 00 40 e2 f2 } //01 00 
		$a_01_1 = {81 fe 17 ca 2b 6e 75 40 8b 77 18 68 76 46 8b 8a e8 } //01 00 
		$a_01_2 = {8b 4b 54 f3 a4 0f b7 43 14 31 c9 31 d2 8d 44 18 28 66 3b 4b 06 73 } //01 00 
		$a_01_3 = {28 01 d8 ff d0 50 ff 55 e8 cd 03 eb fc 55 } //00 00 
	condition:
		any of ($a_*)
 
}