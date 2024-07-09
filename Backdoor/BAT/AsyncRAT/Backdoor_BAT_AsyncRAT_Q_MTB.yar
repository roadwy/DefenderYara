
rule Backdoor_BAT_AsyncRAT_Q_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {04 25 2d 17 26 7e ?? ?? 00 04 fe 06 ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 72 } //2
		$a_03_1 = {01 07 18 16 8d ?? 00 00 01 28 ?? ?? 00 0a 13 07 11 07 08 18 16 } //2
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}