
rule Backdoor_Win32_Zegost_CR_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c8 6a 05 8a 14 16 30 11 59 99 f7 f9 85 d2 75 90 09 0f 00 ff 45 ?? 8b 45 ?? 8b 4d ?? 8b 55 ?? 8b 75 } //1
		$a_03_1 = {57 53 c6 45 ?? 4b c6 45 ?? 45 c6 45 ?? 52 c6 45 ?? 4e c6 45 ?? 45 c6 45 ?? 4c c6 45 ?? 33 c6 45 ?? 32 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c } //1
		$a_01_2 = {66 81 38 4d 5a 0f 85 12 01 00 00 8b 78 3c 03 f8 81 3f 50 45 00 00 0f 85 01 01 00 00 6a 04 68 00 20 00 00 ff 77 50 ff 77 34 ff 55 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}