
rule Backdoor_Win32_Zegost_G{
	meta:
		description = "Backdoor:Win32/Zegost.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 ?? 88 10 40 ?? 75 f4 } //1
		$a_03_1 = {3d 00 00 20 03 73 0d 6a 02 56 56 ff 75 ?? ff 15 } //1
		$a_02_2 = {88 9e b5 00 00 00 c6 45 ?? 48 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 72 c6 45 ?? 74 } //1
		$a_00_3 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 25 64 2e 62 61 6b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}