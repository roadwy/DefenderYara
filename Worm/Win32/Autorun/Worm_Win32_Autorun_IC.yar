
rule Worm_Win32_Autorun_IC{
	meta:
		description = "Worm:Win32/Autorun.IC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4e 6f 4e 61 4d 65 78 44 [0-10] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1
		$a_01_1 = {0d 55 6e 69 74 31 5f 61 75 74 6f 72 75 6e } //1 唍楮ㅴ慟瑵牯湵
		$a_00_2 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SoftWare\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}