
rule Trojan_MacOS_AmosStealer_GAV_MTB{
	meta:
		description = "Trojan:MacOS/AmosStealer.GAV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0e 00 0e 00 0f 00 00 "
		
	strings :
		$a_01_0 = {48 8b 95 38 ff ff ff 48 ff c1 48 39 d1 73 24 4c 89 fa a8 01 75 07 48 8b 95 40 ff ff ff 30 1c 0a 0f b6 95 30 ff ff ff f6 c2 01 0f 94 c0 75 d1 } //14
		$a_01_1 = {5f 75 73 6c 65 65 70 } //1 _usleep
		$a_01_2 = {5f 77 61 69 74 70 69 64 } //1 _waitpid
		$a_01_3 = {5f 77 72 69 74 65 } //1 _write
		$a_01_4 = {64 79 6c 64 5f 73 74 75 62 5f 62 69 6e 64 65 72 } //1 dyld_stub_binder
		$a_01_5 = {72 61 64 72 3a 2f 2f 35 36 31 34 35 34 32 } //1 radr://5614542
		$a_01_6 = {65 78 65 63 6c } //1 execl
		$a_01_7 = {65 78 65 63 76 70 } //1 execvp
		$a_01_8 = {66 6f 72 6b } //1 fork
		$a_01_9 = {6d 65 6d 63 70 79 } //1 memcpy
		$a_01_10 = {6d 65 6d 6d 6f 76 65 } //1 memmove
		$a_01_11 = {2d 69 4c 64 } //1 -iLd
		$a_01_12 = {3f 57 35 2f 3d 5c } //1 ?W5/=\
		$a_01_13 = {2f 2b 75 62 2d 25 } //1 /+ub-%
		$a_01_14 = {2f 62 69 6e 2f 7a 73 68 } //1 /bin/zsh
	condition:
		((#a_01_0  & 1)*14+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=14
 
}