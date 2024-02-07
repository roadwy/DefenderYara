
rule Trojan_Win32_Cycler_MA_MTB{
	meta:
		description = "Trojan:Win32/Cycler.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 04 02 88 01 a1 90 01 04 8b 0d 90 01 04 8d 44 01 f7 a3 90 01 04 a1 90 01 04 33 d2 6a 0c 59 f7 f1 a3 90 01 04 e9 90 00 } //01 00 
		$a_01_1 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_2 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}