
rule VirTool_BAT_Injector_JM{
	meta:
		description = "VirTool:BAT/Injector.JM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 0a 1f 0b 13 05 2b b6 05 04 61 1f 3d 59 06 61 } //1
		$a_01_1 = {26 1f 0a 13 0e 2b a5 03 20 c7 11 5a 0c 61 04 61 0a } //1
		$a_01_2 = {24 39 33 65 38 36 39 37 33 2d 36 30 62 37 2d 34 38 33 37 2d 61 66 39 32 2d 39 34 31 38 39 39 66 62 33 64 63 30 } //1 $93e86973-60b7-4837-af92-941899fb3dc0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}