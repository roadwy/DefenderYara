
rule Backdoor_Win32_Zegost_BQ{
	meta:
		description = "Backdoor:Win32/Zegost.BQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 75 73 65 00 00 00 5b 43 61 70 73 4c 6f 63 6b 5d } //1
		$a_03_1 = {ff 68 c6 85 ?? ff ff ff 6f c6 85 ?? ff ff ff 6e c6 85 ?? ff ff ff 65 c6 85 ?? ff ff ff 2e c6 85 ?? ff ff ff 70 c6 85 ?? ff ff ff 62 c6 85 ?? ff ff ff 6b c6 85 ?? ff ff ff 00 } //1
		$a_01_2 = {c6 45 f0 5c c6 45 f1 6f c6 45 f2 75 c6 45 f3 72 c6 45 f4 6c c6 45 f5 6f c6 45 f6 67 c6 45 f7 2e c6 45 f8 64 c6 45 f9 61 c6 45 fa 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}