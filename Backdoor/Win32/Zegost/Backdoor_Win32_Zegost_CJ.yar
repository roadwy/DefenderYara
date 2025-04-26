
rule Backdoor_Win32_Zegost_CJ{
	meta:
		description = "Backdoor:Win32/Zegost.CJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 77 69 6e 64 6f 77 73 2e 74 64 6c 00 } //1
		$a_01_1 = {25 73 5c 25 64 5f 61 64 65 2e 61 61 61 73 74 } //1 %s\%d_ade.aaast
		$a_01_2 = {54 69 79 61 25 30 38 64 41 49 } //1 Tiya%08dAI
		$a_03_3 = {8b 55 fc 80 04 11 e9 [0-15] 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 } //2
		$a_01_4 = {c7 44 24 24 4d 5a 00 00 c7 44 24 1c 90 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=6
 
}