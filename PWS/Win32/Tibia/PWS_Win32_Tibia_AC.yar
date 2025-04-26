
rule PWS_Win32_Tibia_AC{
	meta:
		description = "PWS:Win32/Tibia.AC,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_03_0 = {05 8d 34 b6 81 c6 ?? ?? 62 00 90 09 16 00 b8 ?? ?? 62 00 e8 ?? ?? ff ff 88 04 24 ?? ?? 0f b6 c3 8b f0 c1 e6 } //10
		$a_03_1 = {ff 0f 1f 00 e8 90 09 04 00 50 6a 00 68 } //10
		$a_03_2 = {7e 27 be 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 32 ff 83 ea 03 e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 46 4b 75 de } //3
		$a_00_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_00_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_5 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //1 GetWindowThreadProcessId
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=23
 
}