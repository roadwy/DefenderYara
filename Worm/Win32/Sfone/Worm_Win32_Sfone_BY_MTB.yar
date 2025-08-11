
rule Worm_Win32_Sfone_BY_MTB{
	meta:
		description = "Worm:Win32/Sfone.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 d8 0f be c0 83 c0 41 88 45 fd 8d 45 fd 50 ff 15 ?? ?? ?? 00 89 44 9d 94 83 c3 01 83 fb 1a 7c } //2
		$a_01_1 = {38 74 78 34 72 37 6c 71 38 6c 37 6f 70 74 67 68 64 37 65 73 30 61 76 6a 69 63 69 76 32 78 31 6e 76 62 77 66 66 6c 35 62 72 79 76 6d 31 } //1 8tx4r7lq8l7optghd7es0avjiciv2x1nvbwffl5bryvm1
		$a_01_2 = {39 36 74 78 66 74 39 66 } //1 96txft9f
		$a_01_3 = {6d 34 6a 75 64 39 76 63 73 35 73 6a 38 69 72 } //1 m4jud9vcs5sj8ir
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}