
rule VirTool_BAT_Obfuscator_BG{
	meta:
		description = "VirTool:BAT/Obfuscator.BG,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 03 09 18 6f 90 01 04 28 90 01 04 28 90 01 04 04 07 6f 90 01 04 28 90 01 04 6a 61 b7 28 90 01 04 28 90 01 04 13 04 06 11 04 6f 90 01 04 26 07 04 6f 90 01 04 17 da 90 00 } //10
		$a_00_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 32 00 30 00 31 00 33 00 28 00 54 00 4d 00 29 00 } //1 Windows 2013(TM)
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}