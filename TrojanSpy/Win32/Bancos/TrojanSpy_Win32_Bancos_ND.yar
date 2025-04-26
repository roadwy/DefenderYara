
rule TrojanSpy_Win32_Bancos_ND{
	meta:
		description = "TrojanSpy:Win32/Bancos.ND,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 00 00 6c 7b 7e 7d 4a 42 45 4b 4c 50 50 56 5e 5c 5c 65 69 65 6c 6e 6f b3 b8 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 32 30 31 2e 31 36 31 2e 34 35 2e 32 31 2f 70 72 69 76 61 74 65 2f 62 6d 70 73 2f 6d 73 62 6f 74 74 6f 6e 2e 67 69 66 } //1 http://201.161.45.21/private/bmps/msbotton.gif
		$a_01_2 = {58 00 00 00 6c 7b 7e 7d 4a 42 45 4b 4c 51 50 56 5b 5b 5c 62 6c 70 68 6e 73 76 75 b2 b9 } //1
		$a_01_3 = {68 74 74 70 3a 2f 2f 32 30 32 2e 31 33 30 2e 31 38 39 2e 31 33 33 2f 69 6d 61 67 65 73 2f 6d 73 62 6f 74 74 6f 6e 2e 67 69 66 00 00 60 } //1
		$a_01_4 = {68 74 74 70 3a 2f 2f 38 33 2e 31 34 30 2e 31 38 34 2e 31 35 32 2f 69 6d 61 67 65 73 2f 6d 73 62 6f 74 74 6f 6e 2e 67 69 66 } //1 http://83.140.184.152/images/msbotton.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}