
rule Trojan_Win32_Cycler_MA_MTB{
	meta:
		description = "Trojan:Win32/Cycler.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 02 88 01 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 44 01 f7 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 d2 6a 0c 59 f7 f1 a3 ?? ?? ?? ?? e9 } //10
		$a_01_1 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}