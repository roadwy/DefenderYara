
rule VirTool_Win32_Obfuscator_AJF{
	meta:
		description = "VirTool:Win32/Obfuscator.AJF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 37 8d 37 b9 22 00 00 00 42 81 fa 54 54 00 00 75 e8 90 09 08 00 33 d2 8d ba 00 00 60 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}