
rule VirTool_BAT_Injector_FY{
	meta:
		description = "VirTool:BAT/Injector.FY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 0f 06 07 06 07 91 03 08 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 eb } //1
		$a_03_1 = {32 e8 12 02 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 11 04 1f 27 } //1
		$a_01_2 = {32 e6 06 17 58 0a 06 02 50 8e 69 32 d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}