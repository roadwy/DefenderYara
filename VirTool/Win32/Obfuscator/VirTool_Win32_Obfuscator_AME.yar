
rule VirTool_Win32_Obfuscator_AME{
	meta:
		description = "VirTool:Win32/Obfuscator.AME,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d6 8b 45 f4 8a 0c 38 ff 05 ?? ?? ?? ?? 2a cb 80 f1 3f 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 dd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}