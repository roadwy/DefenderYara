
rule Trojan_Win32_Tinba_GZN_MTB{
	meta:
		description = "Trojan:Win32/Tinba.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 8b 0d ?? ?? ?? ?? 03 c0 2b 44 24 ?? 2b 44 24 ?? 03 c1 03 44 24 10 01 44 24 2c a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 7d 3b 8b 4c 24 10 41 0f af 4c 24 34 03 4c 24 3c c1 f8 ?? 51 8b 0d 0c 4f 43 00 } //10
		$a_01_1 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //1 GetSystemInfo
		$a_01_2 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}