
rule VirTool_BAT_Injector_FX{
	meta:
		description = "VirTool:BAT/Injector.FX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 0f 02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 eb } //1
		$a_03_1 = {1f 23 9d 11 07 6f ?? ?? ?? ?? 0a 06 8e 69 8d ?? ?? ?? ?? 0b 16 0c 2b 0f 07 08 06 08 9a } //1
		$a_01_2 = {33 2a 16 13 04 2b 06 11 04 17 58 13 04 11 04 09 8e 69 2f 0f 09 11 04 9a 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}