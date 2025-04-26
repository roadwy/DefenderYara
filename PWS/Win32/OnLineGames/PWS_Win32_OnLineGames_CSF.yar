
rule PWS_Win32_OnLineGames_CSF{
	meta:
		description = "PWS:Win32/OnLineGames.CSF,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 56 80 20 00 33 f6 8b 4c 24 08 8a 0c 0e 80 f9 30 7c 11 80 f9 39 7f 0c 8a 10 80 c2 0d c0 e2 04 02 d1 eb 14 80 f9 41 7c 17 80 f9 46 7f 12 8a 10 c0 e2 04 02 d1 80 ea 37 46 88 10 83 fe 02 7c c7 5e c3 } //10
		$a_01_1 = {5c 43 6f 6e 66 69 67 5c 2a 2e 48 65 69 4d 69 6e 67 44 61 6e 2e 74 78 74 } //2 \Config\*.HeiMingDan.txt
		$a_01_2 = {6c 65 67 65 6e 64 20 6f 66 20 6d 69 72 } //1 legend of mir
		$a_01_3 = {4d 69 72 32 42 61 6e 61 6e 61 } //2 Mir2Banana
		$a_01_4 = {25 73 3f 52 45 3d 25 73 26 53 3d 25 73 26 41 3d 25 73 26 50 3d 25 73 26 52 3d 25 73 26 52 47 3d 25 73 26 52 4a 3d 25 73 26 45 3d 25 73 } //2 %s?RE=%s&S=%s&A=%s&P=%s&R=%s&RG=%s&RJ=%s&E=%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=15
 
}