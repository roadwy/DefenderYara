
rule Backdoor_Win32_Hacty_D{
	meta:
		description = "Backdoor:Win32/Hacty.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 24 10 38 1c 16 74 ?? 8b fe 83 c9 ff 33 c0 42 f2 ae f7 d1 49 3b d1 72 } //1
		$a_01_1 = {6d 68 61 63 6b 65 72 79 79 74 68 61 63 31 39 37 37 } //1 mhackeryythac1977
		$a_01_2 = {54 68 65 20 62 61 63 6b 64 6f 6f 72 20 69 73 20 72 75 6e 6e 69 6e 67 } //1 The backdoor is running
		$a_01_3 = {49 6e 6a 65 63 74 54 68 72 65 61 64 3a 22 25 73 22 20 65 72 72 6f 72 20 63 6f 64 65 3a 25 64 } //1 InjectThread:"%s" error code:%d
		$a_01_4 = {4d 6f 64 74 68 2e 46 6c 61 67 3d 25 78 2c 4d 6f 64 74 68 2e 4d 6f 64 69 66 79 4d 6f 64 74 68 3d 25 78 2c 4d 6f 64 74 68 2e 53 74 61 72 74 4d 6f 64 74 68 3d 25 78 } //1 Modth.Flag=%x,Modth.ModifyModth=%x,Modth.StartModth=%x
		$a_01_5 = {42 65 67 69 6e 20 74 6f 20 73 74 61 72 74 20 68 61 63 6b 65 72 27 73 20 64 6f 6f 72 } //1 Begin to start hacker's door
		$a_01_6 = {8a 01 0f b6 71 01 88 45 fb 0f b6 c0 c1 e0 04 33 c6 0f b6 71 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}