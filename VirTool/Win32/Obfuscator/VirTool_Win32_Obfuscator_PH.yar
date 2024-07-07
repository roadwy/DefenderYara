
rule VirTool_Win32_Obfuscator_PH{
	meta:
		description = "VirTool:Win32/Obfuscator.PH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {50 08 8b 4e 90 01 01 6a 90 01 01 6a 90 01 01 6a 90 01 01 89 01 8b 46 90 01 01 6a 90 01 01 ff 50 08 8b 4e 90 01 01 89 01 90 00 01 } //1
		$a_ff_1 = {ff 50 04 85 c0 8b 46 4c 75 08 81 00 90 01 02 00 00 eb 90 } //8448
	condition:
		((#a_13_0  & 1)*1+(#a_ff_1  & 1)*8448) >=2
 
}