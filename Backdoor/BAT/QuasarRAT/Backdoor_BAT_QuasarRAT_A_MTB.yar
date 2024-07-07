
rule Backdoor_BAT_QuasarRAT_A_MTB{
	meta:
		description = "Backdoor:BAT/QuasarRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 17 2d 01 00 02 17 59 45 03 00 00 00 02 00 00 00 1b 00 00 00 12 00 00 00 2b 28 04 14 06 05 14 14 14 16 28 90 01 01 00 00 0a 0b 2b 1c 02 8c 90 01 01 00 00 01 0b 2b 13 04 14 06 05 14 14 14 28 90 00 } //2
		$a_01_1 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 } //1 GetProcessesByName
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}