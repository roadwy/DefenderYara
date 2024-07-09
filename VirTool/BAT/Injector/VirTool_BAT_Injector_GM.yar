
rule VirTool_BAT_Injector_GM{
	meta:
		description = "VirTool:BAT/Injector.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 23 02 06 02 06 91 05 06 04 5d 91 06 1b 58 05 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d7 02 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule VirTool_BAT_Injector_GM_2{
	meta:
		description = "VirTool:BAT/Injector.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 09 91 06 09 08 6f ?? 00 00 0a 5d 91 09 1b 58 06 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 09 17 58 0d 09 07 8e 69 32 d2 07 28 04 00 00 06 2a } //1
		$a_03_1 = {02 06 02 06 91 03 06 04 6f ?? 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d2 } //1
		$a_03_2 = {07 08 07 08 91 02 08 72 ?? 00 00 70 6f ?? 00 00 0a 5d 91 08 1b 58 02 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 08 17 58 0c 08 07 8e 69 32 ac } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}