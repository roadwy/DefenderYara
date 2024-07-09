
rule VirTool_Win32_Obfuscator_OO{
	meta:
		description = "VirTool:Win32/Obfuscator.OO,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 39 32 4c 02 ?? 8b 40 ?? 88 0c 07 8b 45 08 ff 40 ?? 8b 45 08 ff 80 ?? ?? 00 00 [0-02] 8b 45 08 83 78 ?? 04 72 ?? 89 ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}