
rule Worm_Win32_Easymode_A{
	meta:
		description = "Worm:Win32/Easymode.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 66 81 7d b8 4d 5a 74 } //2
		$a_03_1 = {0f be 45 d4 83 f8 61 74 ?? 0f be 55 d4 83 fa 41 74 } //3
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_01_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d } //1 shell\explore\Command=
		$a_00_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}