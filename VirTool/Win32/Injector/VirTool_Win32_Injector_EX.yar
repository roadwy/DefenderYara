
rule VirTool_Win32_Injector_EX{
	meta:
		description = "VirTool:Win32/Injector.EX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 36 8b 3b 03 fd 52 33 d2 c1 c2 03 32 17 47 80 3f 00 75 f5 } //1
		$a_03_1 = {ac 32 c3 aa 43 86 df e2 f7 8b 9d ?? ?? ?? ?? 03 5b 3c } //1
		$a_03_2 = {97 33 c0 2d ?? ?? ?? ?? ab 35 ?? ?? ?? ?? ab 05 ?? ?? ?? ?? ab 35 ?? ?? ?? ?? ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}