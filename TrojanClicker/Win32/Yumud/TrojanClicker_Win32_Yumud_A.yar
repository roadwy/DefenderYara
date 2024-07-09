
rule TrojanClicker_Win32_Yumud_A{
	meta:
		description = "TrojanClicker:Win32/Yumud.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {db 45 fc dd 5d ec dd 45 ec db 45 f8 dd 5d e4 dc 65 e4 dd 5d dc dd 45 dc dc 05 ?? ?? ?? ?? dd 5d d4 dd 45 d4 e8 } //10
		$a_00_1 = {75 72 6c 00 00 68 74 74 70 3a 2f 2f 00 2f 73 3f 00 2f 62 61 69 64 75 3f 00 74 69 74 6c 65 00 3f 71 75 65 72 79 3d 00 2f 00 68 74 74 70 3a 2f 2f 77 77 77 2e } //1
		$a_00_2 = {75 72 6c 00 00 68 74 74 70 3a 2f 2f 00 2f 73 3f 00 2f 62 61 69 64 75 3f 00 3f 71 75 65 72 79 3d 00 2f 00 68 74 74 70 3a 2f 2f 77 77 77 2e } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}