
rule Backdoor_Win32_Zegost_DL{
	meta:
		description = "Backdoor:Win32/Zegost.DL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 08 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c } //2
		$a_01_1 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a } //1
		$a_03_2 = {51 c6 44 24 ?? 5c c6 44 24 ?? 6f c6 44 24 ?? 75 c6 44 24 ?? 72 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 67 c6 44 24 ?? 2e } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=5
 
}