
rule VirTool_Win32_Obfuscator_CF{
	meta:
		description = "VirTool:Win32/Obfuscator.CF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 40 00 00 00 90 02 10 8b 90 01 01 3c 01 90 01 01 8b 90 01 01 50 90 02 08 ff 90 04 01 03 d0 2d d7 90 00 } //1
		$a_03_1 = {81 f8 00 7d 00 00 90 02 10 0f 83 90 01 01 00 00 00 90 02 18 80 fc 05 90 02 10 0f 83 90 01 01 00 00 00 90 02 18 81 f8 7f 00 00 00 90 02 10 0f 87 90 01 01 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}