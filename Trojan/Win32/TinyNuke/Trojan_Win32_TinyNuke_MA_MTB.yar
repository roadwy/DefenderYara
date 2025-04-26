
rule Trojan_Win32_TinyNuke_MA_MTB{
	meta:
		description = "Trojan:Win32/TinyNuke.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 16 ae 92 62 77 c0 c1 62 77 c0 c1 62 77 c0 c1 b1 05 c3 c0 69 77 c0 c1 b1 05 c5 c0 c1 77 c0 c1 } //5
		$a_01_1 = {30 02 c4 c0 73 77 c0 c1 30 02 c3 c0 77 77 c0 c1 a0 9b 0e c1 60 77 c0 c1 b1 05 c1 c0 6f 77 c0 c1 } //5
		$a_01_2 = {5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //2 \Bitcoin\wallet.dat
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_4 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}