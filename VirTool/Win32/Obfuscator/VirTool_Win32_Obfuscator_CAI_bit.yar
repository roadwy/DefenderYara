
rule VirTool_Win32_Obfuscator_CAI_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.CAI!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb d8 c7 45 90 09 23 00 83 ?? 01 89 ?? ec 8b ?? ec 3b ?? cc 73 17 8b ?? f4 03 ?? ec 33 ?? 8a ?? 83 ?? 45 8b ?? fc 03 ?? ec 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}