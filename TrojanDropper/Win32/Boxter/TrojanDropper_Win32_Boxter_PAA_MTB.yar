
rule TrojanDropper_Win32_Boxter_PAA_MTB{
	meta:
		description = "TrojanDropper:Win32/Boxter.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 31 20 2d 43 20 22 [0-24] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 2b [0-08] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 29 3b 70 6f 77 65 72 73 68 65 6c 6c [0-08] 2e 76 61 6c 75 65 2e 74 6f 53 74 72 69 6e 67 28 29 } //10
		$a_03_1 = {22 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 63 6d 64 22 20 2f 63 20 43 3a 5c 54 45 4d 50 5c [0-04] 2e 62 61 74 } //10
		$a_01_2 = {62 00 32 00 65 00 69 00 6e 00 63 00 66 00 69 00 6c 00 65 00 } //10 b2eincfile
		$a_01_3 = {65 00 78 00 74 00 64 00 2e 00 65 00 78 00 65 00 } //10 extd.exe
		$a_01_4 = {40 73 68 69 66 74 20 2f 30 } //10 @shift /0
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=50
 
}