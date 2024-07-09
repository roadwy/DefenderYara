
rule PWS_Win32_OnLineGames_ZFI{
	meta:
		description = "PWS:Win32/OnLineGames.ZFI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 33 63 37 6d 79 63 35 39 [0-0a] 5e 6a 6a 66 30 25 25 27 24 69 57 64 5d 6b 65 6d 5f 6b 69 5d 5c 27 26 26 26 26 24 59 64 25 66 65 69 6a 6e 58 63 25 66 65 69 6a 24 57 69 66 } //2
		$a_01_1 = {3f 67 61 6d 65 54 79 70 65 3d 71 71 73 67 26 5a 6f 6e 65 3d 25 73 26 53 65 72 76 65 72 3d 25 73 26 4e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 26 6e 69 63 6b 4e 61 6d 65 3d 25 73 26 4c 65 76 65 6c 3d 25 73 26 4d 6f 6e 65 79 3d 25 73 26 73 65 63 6f 50 61 73 73 3d 25 73 26 4d 42 3d 25 73 26 43 61 72 64 3d 25 73 3d 25 73 7c 25 73 3d 25 73 7c 25 73 3d 25 73 26 62 61 6e 6b 50 61 73 73 3d 25 73 26 6e 6f 52 65 66 72 65 73 68 43 6f 64 65 3d 25 73 26 68 61 72 64 49 6e 66 6f 3d 25 73 26 70 61 72 61 3d 25 73 26 76 65 72 3d 25 73 } //1 ?gameType=qqsg&Zone=%s&Server=%s&Name=%s&password=%s&nickName=%s&Level=%s&Money=%s&secoPass=%s&MB=%s&Card=%s=%s|%s=%s|%s=%s&bankPass=%s&noRefreshCode=%s&hardInfo=%s&para=%s&ver=%s
		$a_03_2 = {7b 35 46 41 44 43 37 33 43 2d 33 43 45 32 2d 34 37 42 42 2d 42 43 43 36 2d 35 34 35 31 39 33 39 45 33 43 30 41 7d [0-0a] 72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}