
rule Backdoor_Win32_BruteRatel_MA_MTB{
	meta:
		description = "Backdoor:Win32/BruteRatel.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 7a ff cc 74 4b 85 c0 75 03 83 ea 20 8a 1a 80 fb e9 74 06 80 7a 03 e9 75 05 41 31 c0 eb e1 } //1
		$a_01_1 = {31 c0 80 fb b8 75 2d 80 7a 05 e8 75 27 80 7a 06 03 75 21 80 7a 0d 8b 75 1b 80 7a 0e d4 75 15 0f b6 42 02 c1 e0 08 89 c3 0f b6 42 01 09 d8 01 c8 eb 02 31 c0 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}