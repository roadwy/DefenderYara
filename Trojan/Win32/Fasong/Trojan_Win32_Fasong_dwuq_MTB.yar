
rule Trojan_Win32_Fasong_dwuq_MTB{
	meta:
		description = "Trojan:Win32/Fasong.dwuq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 17 89 d0 33 d2 89 17 8b e8 ff d5 83 3f 00 75 ef } //10
		$a_01_1 = {6b 61 76 39 78 2e 65 78 65 } //1 kav9x.exe
		$a_01_2 = {72 61 76 6d 6f 6e 2e 65 78 65 } //1 ravmon.exe
		$a_01_3 = {77 61 74 63 68 65 72 2e 65 78 65 } //1 watcher.exe
		$a_01_4 = {70 61 73 73 77 6f 72 64 67 75 61 72 64 2e 65 78 65 } //1 passwordguard.exe
		$a_80_5 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //autorun.inf  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=15
 
}