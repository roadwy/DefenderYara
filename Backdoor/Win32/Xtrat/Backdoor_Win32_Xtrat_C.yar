
rule Backdoor_Win32_Xtrat_C{
	meta:
		description = "Backdoor:Win32/Xtrat.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 ff d3 33 c0 5a 59 59 64 89 10 } //1
		$a_01_1 = {0f b6 54 1a ff 33 d7 88 54 18 ff 8d 45 f4 } //1
		$a_01_2 = {53 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}