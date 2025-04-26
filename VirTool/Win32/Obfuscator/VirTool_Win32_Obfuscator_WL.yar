
rule VirTool_Win32_Obfuscator_WL{
	meta:
		description = "VirTool:Win32/Obfuscator.WL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d fc 1b 4d ee f7 d1 31 c0 05 5e 09 00 00 40 39 c8 75 90 14 32 d2 01 d8 29 c1 43 8a 53 ff 20 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}