
rule Backdoor_Win32_Prosti_L{
	meta:
		description = "Backdoor:Win32/Prosti.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 89 43 14 66 c7 45 ?? 02 00 56 e8 ?? ?? ?? ?? 66 89 45 ?? 8b 43 04 50 e8 } //1
		$a_01_1 = {50 68 7e 66 04 80 8b 43 14 50 e8 } //1
		$a_03_2 = {68 7f 66 04 40 8b 43 14 50 e8 ?? ?? ?? ?? 40 75 ?? c7 04 24 ff ff ff ff 8b c3 e8 ?? ?? ?? ?? eb ?? 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}