
rule PUA_Win32_FlashHelper{
	meta:
		description = "PUA:Win32/FlashHelper,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 6c 00 61 00 73 00 68 00 48 00 65 00 6c 00 70 00 65 00 72 00 20 00 54 00 61 00 73 00 6b 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 43 00 6f 00 72 00 65 00 20 00 32 00 74 00 68 00 } //1 FlashHelper TaskMachineCore 2th
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 6d 00 69 00 6e 00 69 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //1 Software\Microsoft\Windows\CurrentVersion\miniconfig
		$a_01_2 = {6d 00 69 00 6e 00 69 00 2e 00 66 00 66 00 6e 00 65 00 77 00 73 00 2e 00 63 00 6e 00 } //1 mini.ffnews.cn
		$a_01_3 = {6e 00 65 00 78 00 74 00 5f 00 6f 00 70 00 65 00 6e 00 5f 00 69 00 6e 00 74 00 65 00 72 00 76 00 61 00 6c 00 } //1 next_open_interval
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}