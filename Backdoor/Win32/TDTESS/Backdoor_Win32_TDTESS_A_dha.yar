
rule Backdoor_Win32_TDTESS_A_dha{
	meta:
		description = "Backdoor:Win32/TDTESS.A!dha,SIGNATURE_TYPE_PEHSTR,28 00 28 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 00 32 00 6c 00 75 00 62 00 47 00 39 00 6e 00 61 00 57 00 34 00 6c 00 } //10 d2lubG9naW4l
		$a_01_1 = {64 00 32 00 6c 00 75 00 62 00 47 00 39 00 6e 00 61 00 57 00 34 00 6b 00 } //10 d2lubG9naW4k
		$a_01_2 = {64 00 32 00 6c 00 75 00 62 00 47 00 39 00 6e 00 61 00 57 00 34 00 71 00 } //10 d2lubG9naW4q
		$a_01_3 = {33 00 44 00 39 00 42 00 39 00 34 00 41 00 39 00 38 00 42 00 2d 00 37 00 36 00 41 00 38 00 2d 00 34 00 38 00 31 00 30 00 2d 00 42 00 31 00 41 00 30 00 2d 00 34 00 42 00 45 00 37 00 43 00 34 00 46 00 39 00 43 00 39 00 38 00 44 00 41 00 32 00 23 00 } //10 3D9B94A98B-76A8-4810-B1A0-4BE7C4F9C98DA2#
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 } //20 C:\Users\admin\Documents\visual studio 
		$a_01_5 = {5c 54 44 54 45 53 53 5f 53 68 6f 72 74 4f 6e 65 5c } //20 \TDTESS_ShortOne\
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20) >=40
 
}