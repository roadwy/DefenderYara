
rule Trojan_Win32_TrickBot_VSD_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.VSD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 0e 00 00 "
		
	strings :
		$a_01_0 = {64 74 64 4b 4b 79 67 46 6f 76 72 4b } //2 dtdKKygFovrK
		$a_01_1 = {65 7a 54 32 4f 6e 37 37 69 48 52 43 35 55 53 48 } //2 ezT2On77iHRC5USH
		$a_01_2 = {66 76 35 4e 68 64 4c 52 70 44 4a 45 76 74 65 79 50 72 } //2 fv5NhdLRpDJEvteyPr
		$a_01_3 = {6a 6b 30 74 4a 53 30 63 33 4a 7a 30 63 70 56 46 69 69 50 } //2 jk0tJS0c3Jz0cpVFiiP
		$a_01_4 = {66 37 52 34 33 35 65 78 51 43 37 71 7a 59 4f 65 65 72 7a } //2 f7R435exQC7qzYOeerz
		$a_01_5 = {67 4e 4e 38 7a 34 46 45 38 4a 37 6a 4d 49 41 6e 69 30 49 67 } //2 gNN8z4FE8J7jMIAni0Ig
		$a_01_6 = {66 71 31 6e 70 67 54 5a 55 45 6e 70 6a 50 59 70 6f 66 6a 44 } //2 fq1npgTZUEnpjPYpofjD
		$a_01_7 = {67 77 4a 41 54 5a 53 32 31 43 62 64 52 43 69 48 59 4d 55 56 6a } //2 gwJATZS21CbdRCiHYMUVj
		$a_01_8 = {67 74 64 79 57 44 30 51 63 42 78 32 67 6d 6e 6a 75 31 65 50 54 } //2 gtdyWD0QcBx2gmnju1ePT
		$a_01_9 = {67 37 7a 73 31 4c 34 4e 4d 74 49 4b 44 38 45 61 63 70 61 44 30 4d } //2 g7zs1L4NMtIKD8EacpaD0M
		$a_01_10 = {67 41 54 51 56 77 46 5a 51 66 46 7a 46 56 64 6f 46 74 52 77 33 51 50 } //2 gATQVwFZQfFzFVdoFtRw3QP
		$a_01_11 = {68 52 62 62 6c 6d 34 6e 72 65 36 52 53 6c 34 79 54 44 65 58 54 76 65 6a } //2 hRbblm4nre6RSl4yTDeXTvej
		$a_01_12 = {68 71 4d 70 6d 74 49 44 4f 70 71 58 72 65 43 5a 4a 45 56 38 69 52 78 62 74 6b } //2 hqMpmtIDOpqXreCZJEV8iRxbtk
		$a_01_13 = {69 4b 77 78 4a 44 53 6b 30 75 4a 73 6d 4b 36 76 74 67 67 55 58 4e 38 70 44 76 62 } //2 iKwxJDSk0uJsmK6vtggUXN8pDvb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2) >=2
 
}