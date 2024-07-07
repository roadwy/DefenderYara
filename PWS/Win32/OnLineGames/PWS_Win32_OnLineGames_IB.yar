
rule PWS_Win32_OnLineGames_IB{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 4e 46 2e 65 78 65 } //2 DNF.exe
		$a_01_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //1 User-Agent: Mozilla/4.0
		$a_01_2 = {8b 44 24 08 8a da 03 c2 f6 d3 32 18 32 d9 42 3b 54 24 0c 88 18 7c e9 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=4
 
}
rule PWS_Win32_OnLineGames_IB_2{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 54 4d 42 3a 00 } //1 呄䉍:
		$a_00_1 = {50 41 53 41 3a 00 } //1 䅐䅓:
		$a_00_2 = {25 73 5c 6a 61 76 61 5c 74 72 75 73 74 6c 69 62 5c 25 73 00 } //1 猥橜癡屡牴獵汴扩╜s
		$a_00_3 = {3f 64 6f 3d 74 72 26 63 3d 71 26 69 3d 25 73 } //1 ?do=tr&c=q&i=%s
		$a_03_4 = {83 f8 03 74 05 83 f8 04 75 90 01 01 68 20 40 00 00 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}
rule PWS_Win32_OnLineGames_IB_3{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 63 20 63 6f 6e 66 69 67 20 63 72 79 70 74 73 76 63 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 00 00 6e 65 74 20 73 74 6f 70 20 63 72 79 70 74 73 76 63 00 00 00 6d 6d 67 6c 25 64 2e 64 6c 6c 00 00 25 73 64 6c 6c 63 61 63 68 65 5c 25 73 } //1
		$a_03_1 = {6a 02 68 6c fb ff ff 56 ff 15 90 01 04 56 68 94 04 00 00 6a 01 90 00 } //1
		$a_03_2 = {59 85 c0 59 74 4f 8b 0d 90 01 04 47 81 c5 04 01 00 00 3b f9 7c e1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule PWS_Win32_OnLineGames_IB_4{
	meta:
		description = "PWS:Win32/OnLineGames.IB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {7c 6d 69 6e 69 69 65 2e 65 78 65 7c 33 36 30 73 65 2e 65 78 65 7c } //1 |miniie.exe|360se.exe|
		$a_01_1 = {7c 66 69 72 65 66 6f 78 2e 65 78 65 7c 6d 61 78 74 68 6f 6e 2e 65 78 65 7c 74 74 72 61 76 65 6c 65 72 2e 65 78 65 } //1 |firefox.exe|maxthon.exe|ttraveler.exe
		$a_01_2 = {2e 61 73 70 3f 64 6f 3d 63 68 65 63 6b 00 } //1 愮灳搿㵯档捥k
		$a_01_3 = {67 6f 6c 64 5f 63 6f 69 6e 00 } //1 潧摬损楯n
		$a_02_4 = {3f 55 73 65 72 4e 61 6d 65 3d 90 02 10 26 50 61 73 73 77 6f 72 64 3d 90 02 10 26 50 90 02 10 6e 61 6d 65 3d 90 00 } //1
		$a_02_5 = {26 63 61 72 64 70 61 73 73 3d 90 02 10 26 63 61 72 64 6e 75 6d 3d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}