
rule VirTool_Win32_Obfuscator_DU{
	meta:
		description = "VirTool:Win32/Obfuscator.DU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 6a 00 68 ?? 3a 5c ?? 54 ff d0 83 c4 08 83 f8 01 75 01 cc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}