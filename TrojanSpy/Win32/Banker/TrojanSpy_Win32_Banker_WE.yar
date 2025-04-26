
rule TrojanSpy_Win32_Banker_WE{
	meta:
		description = "TrojanSpy:Win32/Banker.WE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_01_0 = {67 49 67 49 47 71 6c 36 47 30 77 36 75 70 77 37 47 56 30 38 6b 74 4e 30 37 6e 52 55 6f 4b 4d 43 6b 4b 4b 58 71 79 54 41 6e 4e 42 76 61 63 4b 79 6c 64 4f 77 6f 44 } //3 gIgIGql6G0w6upw7GV08ktN07nRUoKMCkKKXqyTAnNBvacKyldOwoD
		$a_01_1 = {41 77 33 4a 53 66 59 61 64 4f 72 57 43 52 33 44 6d 75 31 6b 43 59 69 54 64 70 48 } //3 Aw3JSfYadOrWCR3Dmu1kCYiTdpH
		$a_01_2 = {4b 59 49 52 30 44 54 6f 68 35 4b 33 } //2 KYIR0DToh5K3
		$a_01_3 = {63 59 2f 59 62 38 44 63 69 2f 65 6e 4e 70 34 74 68 35 49 } //2 cY/Yb8Dci/enNp4th5I
		$a_01_4 = {61 51 66 6e 58 4c 50 79 65 6d 7a 39 61 2b 49 41 55 63 4d } //3 aQfnXLPyemz9a+IAUcM
		$a_01_5 = {69 55 41 41 4d 78 65 75 7a 73 33 7a 42 50 70 72 } //1 iUAAMxeuzs3zBPpr
		$a_01_6 = {4b 59 49 52 78 6a 68 61 30 4d 2f 6d 46 33 73 6e 62 48 4e } //1 KYIRxjha0M/mF3snbHN
		$a_01_7 = {61 30 76 33 6e 39 42 } //1 a0v3n9B
		$a_01_8 = {64 6f 52 43 55 6d 36 44 45 77 4c 4e 65 32 49 42 71 71 36 6f 35 42 } //1 doRCUm6DEwLNe2IBqq6o5B
		$a_01_9 = {4b 59 49 52 78 6a 68 61 68 45 6f 6c 33 30 68 4b } //1 KYIRxjhahEol30hK
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=3
 
}