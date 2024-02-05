
rule VirTool_Win32_Obfuscator_EJ{
	meta:
		description = "VirTool:Win32/Obfuscator.EJ,SIGNATURE_TYPE_PEHSTR,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 ca ba 04 00 00 00 83 c7 03 83 c7 15 83 fa 04 75 ee ff d2 51 } //01 00 
		$a_01_1 = {bb 5b 22 2d 31 01 f9 03 15 3e 93 40 00 81 fb 5b 22 2d 31 75 eb ff 15 20 80 40 00 89 cf } //01 00 
		$a_01_2 = {83 eb 33 89 da b9 02 00 00 00 51 ff 15 1c 80 40 00 8b 3c 24 5f 39 d3 74 03 83 ef 0b ff 15 00 80 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}