
rule VirTool_Win32_Obfuscator_CAF_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.CAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb d5 ff 75 c4 ff 55 fc 90 09 26 00 83 ?? 01 89 ?? dc 8b ?? dc 3b ?? bc 73 1a 8b ?? e4 03 ?? dc 33 ?? 8a ?? 81 ?? ?? 00 00 00 8b ?? fc 03 ?? dc 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}