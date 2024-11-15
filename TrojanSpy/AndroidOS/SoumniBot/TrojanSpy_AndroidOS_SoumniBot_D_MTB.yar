
rule TrojanSpy_AndroidOS_SoumniBot_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SoumniBot.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 6f 75 79 69 6e 2f 73 6f 66 74 77 61 72 65 61 70 70 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/douyin/softwareapp/MainActivity
		$a_03_1 = {70 10 9e 05 03 00 22 00 f1 11 70 10 3d 87 00 00 62 01 ?? 4b 6e 10 08 4b 01 00 0c 02 6e 10 09 4b 01 00 0c 01 6e 30 9b 87 20 01 0c 00 22 01 19 16 70 10 12 ac 01 00 6e 20 70 87 10 00 0c 00 6e 10 42 87 00 00 0c 00 5b 30 ?? 26 22 00 93 01 71 00 00 0a 00 00 0c 01 70 20 d9 09 10 00 5b 30 ?? 26 22 00 93 1c 70 20 fc dc 30 00 5b 30 ?? 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}