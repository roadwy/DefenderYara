
rule VirTool_BAT_Injector_JA{
	meta:
		description = "VirTool:BAT/Injector.JA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 03 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 b5 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}