
rule VirTool_BAT_Injector_FW{
	meta:
		description = "VirTool:BAT/Injector.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 35 35 48 38 42 48 45 43 48 38 33 48 45 34 48 46 38 48 35 31 48 35 33 48 33 33 48 43 30 48 35 36 48 35 37 48 33 33 48 44 32 48 43 36 48 34 34 48 32 34 48 } //2 H55H8BHECH83HE4HF8H51H53H33HC0H56H57H33HD2HC6H44H24H
		$a_01_1 = {16 1b 9c 11 06 17 20 9b 00 00 00 9c 11 06 18 20 f2 00 00 00 9c 11 06 19 1f 37 9c } //1
		$a_01_2 = {16 1b 9c 07 17 20 9b 00 00 00 9c 07 18 20 f2 00 00 00 9c 07 19 1f 37 9c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}