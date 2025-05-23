
rule Trojan_Win32_Horst_gen_H{
	meta:
		description = "Trojan:Win32/Horst.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 03 8d 4c 24 30 aa e8 87 fd ff ff 68 04 01 00 00 8d 84 24 b4 00 00 00 50 68 ?? ?? 45 00 89 9c 24 d8 01 00 00 } //4
		$a_01_1 = {68 74 73 74 66 6c 64 2e 74 6d 70 00 } //1
		$a_01_2 = {3f 73 3d 37 26 69 64 3d 00 } //1
		$a_01_3 = {67 65 74 46 72 69 65 6e 64 73 20 45 72 72 6f 72 } //1 getFriends Error
		$a_01_4 = {66 72 69 65 6e 64 73 5f 77 72 61 70 70 65 72 00 } //1 牦敩摮彳牷灡数r
		$a_01_5 = {46 72 69 65 6e 64 73 4c 69 73 74 50 61 67 65 00 } //1 牆敩摮䱳獩側条e
		$a_01_6 = {71 75 65 73 74 61 6e 73 77 65 72 00 } //1 畱獥慴獮敷r
		$a_01_7 = {46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 20 00 7c 00 20 00 48 00 6f 00 6d 00 65 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}