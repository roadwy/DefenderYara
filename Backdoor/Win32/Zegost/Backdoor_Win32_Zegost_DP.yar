
rule Backdoor_Win32_Zegost_DP{
	meta:
		description = "Backdoor:Win32/Zegost.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 3e c6 45 ?? 46 c6 45 ?? 55 c6 45 ?? 43 c6 45 ?? 4b c6 45 ?? 33 } //2
		$a_01_1 = {8a 06 32 c2 02 c2 88 06 46 49 75 } //1
		$a_01_2 = {25 73 20 2f 76 20 22 25 73 5c 63 6f 6e 66 69 67 5c 73 61 6d 22 20 22 25 73 64 66 65 72 2e 64 61 74 } //1 %s /v "%s\config\sam" "%sdfer.dat
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}