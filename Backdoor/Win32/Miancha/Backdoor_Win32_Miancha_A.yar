
rule Backdoor_Win32_Miancha_A{
	meta:
		description = "Backdoor:Win32/Miancha.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {78 c6 44 24 ?? 7d c6 44 24 ?? 72 c6 44 24 ?? 67 c6 44 24 ?? 3a c6 44 24 ?? 7b c6 44 24 ?? 77 c6 44 24 ?? 6c c6 44 24 ?? 14 [0-05] c6 44 24 ?? 65 [0-03] 80 30 14 75 } //1
		$a_01_1 = {74 65 6d 70 5c 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 70 64 66 } //1 temp\instructions.pdf
		$a_01_2 = {43 6f 6e 31 00 00 00 00 43 6f 6e 33 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}