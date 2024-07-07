
rule Spammer_Win32_Fifesock_B{
	meta:
		description = "Spammer:Win32/Fifesock.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 83 f9 7c 75 1e 8b 90 01 01 fc c6 90 01 01 00 8b 45 fc 83 c0 01 89 45 fc 90 00 } //2
		$a_03_1 = {ff 05 76 0c c7 05 90 01 04 01 00 00 80 eb 0a c7 05 90 01 04 02 00 00 80 90 09 05 00 83 bd 90 00 } //2
		$a_01_2 = {5f 42 4c 4f 43 4b 45 44 5f 31 38 30 38 34 } //1 _BLOCKED_18084
		$a_01_3 = {25 73 3f 61 63 74 3d 66 62 5f 67 65 74 } //1 %s?act=fb_get
		$a_01_4 = {25 73 3f 61 63 74 3d 66 62 5f 65 78 74 65 6e 64 65 64 } //1 %s?act=fb_extended
		$a_01_5 = {25 73 3f 61 63 74 3d 66 62 5f 73 74 61 74 26 6e 75 6d 3d 25 64 } //1 %s?act=fb_stat&num=%d
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}