
rule VirTool_Win32_Obfuscator_KD{
	meta:
		description = "VirTool:Win32/Obfuscator.KD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_05_0 = {68 d8 1c 0c 00 } //1
	condition:
		((#a_05_0  & 1)*1) >=1
 
}