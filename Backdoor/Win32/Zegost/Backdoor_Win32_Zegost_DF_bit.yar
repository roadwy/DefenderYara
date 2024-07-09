
rule Backdoor_Win32_Zegost_DF_bit{
	meta:
		description = "Backdoor:Win32/Zegost.DF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 99 f7 f9 8b 74 24 0c 80 c2 ?? 85 f6 76 10 8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_03_1 = {8b 44 24 08 53 55 56 66 81 38 4d 5a 57 74 08 5f 5e 5d 33 c0 5b 59 c3 8b 78 3c 03 f8 89 7c ?? 10 81 3f 50 45 00 00 } //1
		$a_03_2 = {50 c6 44 24 ?? 44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64 c6 44 24 ?? 72 c6 44 24 ?? 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}