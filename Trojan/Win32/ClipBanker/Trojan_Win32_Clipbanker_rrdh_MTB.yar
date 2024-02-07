
rule Trojan_Win32_Clipbanker_rrdh_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.rrdh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //01 00  GetSystemInfo
		$a_01_1 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {68 56 41 78 74 79 66 77 79 66 73 77 74 79 64 66 77 } //01 00  hVAxtyfwyfswtydfw
		$a_01_6 = {72 54 41 73 65 74 72 64 66 72 77 79 75 65 71 65 33 35 36 5f 72 74 6c 73 65 63 75 72 65 6d 65 6d 72 6f 79 67 41 53 } //01 00  rTAsetrdfrwyueqe356_rtlsecurememroygAS
		$a_01_7 = {35 36 5f 72 74 6c 73 25 63 75 72 65 6d 65 6d 72 6f 79 67 41 53 } //01 00  56_rtls%curememroygAS
		$a_01_8 = {72 54 41 73 65 74 72 64 66 72 77 79 75 65 71 65 33 35 36 5f 72 } //01 00  rTAsetrdfrwyueqe356_r
		$a_01_9 = {59 4b 57 65 74 72 64 66 72 77 29 30 65 71 29 32 36 36 } //01 00  YKWetrdfrw)0eq)266
		$a_01_10 = {66 71 65 30 35 36 5f 73 74 6c 72 6e 53 77 72 58 6d 65 6d 72 6f 79 67 69 57 } //00 00  fqe056_stlrnSwrXmemroygiW
	condition:
		any of ($a_*)
 
}