
rule Backdoor_Win32_Zegost_DG_bit{
	meta:
		description = "Backdoor:Win32/Zegost.DG!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 90 01 01 88 10 40 4e 75 f4 90 00 } //1
		$a_01_1 = {44 6c 6c 4d 61 69 6e 2e 64 6c 6c 00 53 68 65 6c 6c 65 78 00 } //2
		$a_01_2 = {5c 54 65 6e 63 65 6e 74 5c 55 73 65 72 73 5c 2a 2e 2a } //1 \Tencent\Users\*.*
		$a_01_3 = {25 2d 32 34 73 20 25 2d 31 35 73 } //1 %-24s %-15s
		$a_01_4 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e } //1 Http/1.1 403 Forbidden
		$a_01_5 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 74 65 72 6d 73 72 76 5f 74 2e 64 6c 6c } //1 %SystemRoot%\system32\termsrv_t.dll
		$a_03_6 = {5b 42 41 43 4b 53 50 41 43 45 5d 90 02 06 5b 44 45 4c 45 54 45 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=6
 
}