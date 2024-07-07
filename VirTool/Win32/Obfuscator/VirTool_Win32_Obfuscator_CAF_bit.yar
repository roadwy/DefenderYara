
rule VirTool_Win32_Obfuscator_CAF_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.CAF!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb d5 ff 75 c4 ff 55 fc 90 09 26 00 83 90 01 01 01 89 90 01 01 dc 8b 90 01 01 dc 3b 90 01 01 bc 73 1a 8b 90 01 01 e4 03 90 01 01 dc 33 90 01 01 8a 90 01 01 81 90 01 02 00 00 00 8b 90 01 01 fc 03 90 01 01 dc 88 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}