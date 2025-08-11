
rule TrojanSpy_AndroidOS_Banker_AR_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AR!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 1c ff ff a2 1c 1c 04 18 1e 00 00 ff ff 00 00 ff ff a2 1c 1c 1e a0 1a 1a 1c 13 02 10 00 a4 1a 1a 02 05 00 1a 00 84 02 8f 28 60 02 8e 00 60 0a ad 00 d2 aa 3d e9 b6 a2 3c 02 08 00 08 02 16 00 02 11 08 00 } //1
		$a_01_1 = {22 04 a1 00 70 10 fa 03 04 00 6e 20 fc 03 24 00 0c 02 71 00 d8 03 00 00 0b 04 13 06 0a 00 83 66 cd 64 8a 44 b7 04 6e 20 fb 03 42 00 0c 02 6e 10 fd 03 02 00 0c 02 d8 00 00 01 } //1
		$a_01_2 = {6e 20 ea 03 08 00 0a 05 6e 20 f1 03 53 00 0a 05 e0 05 05 04 d8 06 00 01 6e 20 ea 03 68 00 0a 06 6e 20 f1 03 63 00 0a 06 b6 65 6e 20 6f 03 54 00 d8 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}