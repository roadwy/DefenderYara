
rule PWS_Win32_OnLineGames_IZ_dll{
	meta:
		description = "PWS:Win32/OnLineGames.IZ!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 3c 38 c6 44 24 3d 39 c6 44 24 3e 2b c6 44 24 3f 2f 33 c0 38 4c 04 00 74 06 40 83 f8 3f 7e f4 83 c4 40 c3 } //2
		$a_01_1 = {8a da 8a 4d 02 80 e2 03 c0 eb 02 88 5c 24 10 8a d8 c0 e2 04 c0 eb 04 0a d3 24 0f 88 54 24 11 8a d1 c0 e0 02 c0 ea 06 0a c2 80 e1 3f } //2
		$a_01_2 = {4b 42 44 4c 6f 67 65 72 } //2 KBDLoger
		$a_01_3 = {5c 68 65 78 69 6c 2e 64 6c 6c } //1 \hexil.dll
		$a_01_4 = {68 70 69 67 5f 57 53 32 2e 64 61 74 } //1 hpig_WS2.dat
		$a_01_5 = {44 2d 77 69 6e 64 6f 77 6e 61 6d 65 2e 74 78 74 } //1 D-windowname.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}