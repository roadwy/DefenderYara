
rule VirTool_Win32_Injector_gen_EU{
	meta:
		description = "VirTool:Win32/Injector.gen!EU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {69 c9 9b cf 62 00 2b c1 2d dc 25 d7 02 89 45 ?? 8b 55 ?? 33 c0 (8b 4d ?? 8a 42 10 8a 42|10 8b 4d )} //2
		$a_03_1 = {b9 30 00 00 00 33 c0 8d bd ?? ?? ?? ?? f3 ab 66 ab c7 45 fc ?? ?? ?? ?? 8b 55 fc 52 90 09 0e 00 66 8b 0d ?? ?? ?? ?? 66 89 8d } //1
		$a_02_2 = {00 59 41 70 70 2e 45 58 45 90 05 01 02 5c 2f 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}