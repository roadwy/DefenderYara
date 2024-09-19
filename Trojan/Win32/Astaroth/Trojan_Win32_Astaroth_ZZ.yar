
rule Trojan_Win32_Astaroth_ZZ{
	meta:
		description = "Trojan:Win32/Astaroth.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,34 03 34 03 08 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //500
		$a_01_1 = {0f b7 00 83 e8 41 8d 04 80 8d 04 80 8b 55 fc 0f b7 52 02 83 ea 41 03 c2 } //100
		$a_01_2 = {8a 54 0a ff 80 ea 0a f6 d2 b9 00 00 00 00 e8 } //100
		$a_01_3 = {0f b7 44 50 fe 33 45 dc 89 45 d8 } //100
		$a_81_4 = {78 47 45 52 41 4c 2e 41 52 } //10 xGERAL.AR
		$a_81_5 = {78 54 52 41 56 41 } //10 xTRAVA
		$a_81_6 = {61 75 69 64 2e 6c 6f 67 } //10 auid.log
		$a_81_7 = {4e 6f 6d 65 20 4d 65 6d 6f 72 79 3a } //10 Nome Memory:
	condition:
		((#a_01_0  & 1)*500+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10) >=820
 
}