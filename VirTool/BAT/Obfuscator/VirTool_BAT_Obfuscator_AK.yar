
rule VirTool_BAT_Obfuscator_AK{
	meta:
		description = "VirTool:BAT/Obfuscator.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 43 6f 72 45 78 65 4d 61 69 6e } //1 _CorExeMain
		$a_01_1 = {20 dd 5b b4 7c 20 b7 29 29 64 61 20 b2 2e fe 4e 20 6b 28 84 58 61 59 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}