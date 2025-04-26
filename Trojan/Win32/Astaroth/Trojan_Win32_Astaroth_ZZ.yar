
rule Trojan_Win32_Astaroth_ZZ{
	meta:
		description = "Trojan:Win32/Astaroth.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,34 03 34 03 08 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //500
		$a_03_1 = {0f b7 00 83 e8 41 8d 04 80 8d 04 80 8b 55 ?? 0f b7 52 02 83 ea 41 03 c2 } //100
		$a_01_2 = {8a 54 0a ff 80 ea 0a f6 d2 b9 00 00 00 00 e8 } //100
		$a_01_3 = {0f b7 44 50 fe 33 45 } //100
		$a_81_4 = {78 47 45 52 41 4c 2e 41 52 } //10 xGERAL.AR
		$a_81_5 = {42 75 69 6c 64 41 76 42 61 6e 6b 73 } //10 BuildAvBanks
		$a_81_6 = {44 65 6c 65 74 65 56 65 72 69 66 69 63 61 4f 46 46 78 } //10 DeleteVerificaOFFx
		$a_81_7 = {76 65 72 69 66 69 63 61 42 6c 6f 71 73 50 72 65 76 } //10 verificaBloqsPrev
	condition:
		((#a_01_0  & 1)*500+(#a_03_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*10+(#a_81_7  & 1)*10) >=820
 
}