
rule Trojan_Win32_Emotet_ED{
	meta:
		description = "Trojan:Win32/Emotet.ED,SIGNATURE_TYPE_PEHSTR,01 00 01 00 0c 00 00 "
		
	strings :
		$a_01_0 = {49 4b 6c 6c 6c 51 57 67 62 68 65 6a 6b 57 45 4a 4b 48 77 37 5c 5c 77 65 72 72 6e 4a 45 4b 4c 4a 33 32 68 6a 65 6c 6b 6b 2e 50 44 42 } //1 IKlllQWgbhejkWEJKHw7\\werrnJEKLJ32hjelkk.PDB
		$a_01_1 = {72 65 6a 34 32 79 34 68 65 72 5c 5c 68 6a 65 72 74 5c 5c 77 74 6a 65 72 68 72 65 68 2e 70 64 62 } //1 rej42y4her\\hjert\\wtjerhreh.pdb
		$a_01_2 = {34 69 63 65 6d 61 6e 4a 67 75 73 65 64 } //1 4icemanJgused
		$a_01_3 = {78 52 6c 4d 70 71 4c 53 61 6c 75 4d 2e 70 64 62 } //1 xRlMpqLSaluM.pdb
		$a_01_4 = {35 33 33 34 67 34 32 67 5c 5c 65 68 72 65 5c 5c 65 68 23 48 45 4e 72 2e 70 64 62 } //1 5334g42g\\ehre\\eh#HENr.pdb
		$a_01_5 = {65 61 46 42 34 37 23 6a 31 74 33 63 70 4a 49 62 4d 71 44 33 34 2e 70 64 62 } //1 eaFB47#j1t3cpJIbMqD34.pdb
		$a_01_6 = {23 69 6b 78 36 75 21 4f 2a 4b 57 2b 2a 4c 76 30 71 4b 66 2e 70 64 62 } //1 #ikx6u!O*KW+*Lv0qKf.pdb
		$a_01_7 = {59 6d 41 47 78 66 31 52 2e 2e 70 64 62 } //1 YmAGxf1R..pdb
		$a_01_8 = {36 7a 79 41 36 40 32 36 37 3d 48 50 53 2e 43 7c 64 4d 71 64 34 2d 71 61 4e 7c 79 6a 6d 2e 70 64 62 } //1 6zyA6@267=HPS.C|dMqd4-qaN|yjm.pdb
		$a_01_9 = {6b 4e 78 45 6e 45 4a 2a 58 3d 62 3d 38 75 33 2b 6f 23 36 4c 39 77 39 64 67 35 39 36 2e 70 64 62 } //1 kNxEnEJ*X=b=8u3+o#6L9w9dg596.pdb
		$a_01_10 = {6b 4a 52 47 45 57 21 23 48 57 52 77 5c 5c 5c 45 57 4a 52 45 52 57 68 6c 6b 77 52 6a 40 23 57 4b 4c 48 4b 45 3a 4c 2e 70 64 62 } //1 kJRGEW!#HWRw\\\EWJRERWhlkwRj@#WKLHKE:L.pdb
		$a_01_11 = {33 5c 5c 71 77 68 57 23 6a 65 72 6a 77 5c 65 72 6a 77 23 48 4a 45 52 6a 77 72 5c 5c 2e 70 64 62 } //1 3\\qwhW#jerjw\erjw#HJERjwr\\.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=1
 
}