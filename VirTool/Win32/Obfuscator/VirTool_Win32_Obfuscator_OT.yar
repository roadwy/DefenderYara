
rule VirTool_Win32_Obfuscator_OT{
	meta:
		description = "VirTool:Win32/Obfuscator.OT,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bf 00 00 00 00 f7 d7 33 f8 f7 d7 6b db 00 ff 75 0c 53 53 53 68 3f 00 0f 00 ff 75 08 ff d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}