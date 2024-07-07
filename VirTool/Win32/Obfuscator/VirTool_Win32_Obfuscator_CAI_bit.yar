
rule VirTool_Win32_Obfuscator_CAI_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.CAI!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb d8 c7 45 90 09 23 00 83 90 01 01 01 89 90 01 01 ec 8b 90 01 01 ec 3b 90 01 01 cc 73 17 8b 90 01 01 f4 03 90 01 01 ec 33 90 01 01 8a 90 01 01 83 90 01 01 45 8b 90 01 01 fc 03 90 01 01 ec 88 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}