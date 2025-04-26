
rule VirTool_BAT_Injector_gen_E{
	meta:
		description = "VirTool:BAT/Injector.gen!E,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 41 00 53 00 53 00 57 00 49 00 4e 00 } //1 PASSWIN
		$a_01_1 = {25 00 57 00 49 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 25 00 } //1 %WINLOGON%
		$a_01_2 = {5c 00 76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1 \v2.0.50727\vbc.exe
		$a_01_3 = {43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 62 00 6c 00 65 00 5f 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 Configurable_Injector.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}