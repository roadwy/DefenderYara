
rule Backdoor_Win32_Chadivendo_STF{
	meta:
		description = "Backdoor:Win32/Chadivendo.STF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 7c 3e fe 52 75 ?? 80 7c 3e fd 49 75 ?? 80 7c 3e fc 44 75 ?? 80 7c 3e fb 3c } //1
		$a_03_1 = {ba 01 01 00 00 66 3b c2 74 ?? ba 01 02 00 00 66 3b c2 74 ?? ba 01 04 00 00 66 3b c2 74 ?? ba 01 08 00 00 66 3b c2 } //1
		$a_02_2 = {68 74 74 70 3a 2f 2f 25 73 [0-20] 25 30 38 78 2e 74 78 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}