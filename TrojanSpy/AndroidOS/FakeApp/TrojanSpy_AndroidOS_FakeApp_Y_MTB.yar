
rule TrojanSpy_AndroidOS_FakeApp_Y_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 60 1f 00 67 05 6e 10 47 2a 00 00 0c 00 6e 10 8f 1a 00 00 54 50 d9 11 54 00 ec 11 6e 10 ed 28 00 00 0a 00 12 01 01 12 } //1
		$a_01_1 = {5b 34 e0 11 60 04 3e 05 12 00 70 40 12 17 53 40 12 14 23 44 6d 24 14 01 d4 00 01 01 12 02 4b 01 04 02 5b 34 db 11 5b 36 de 11 60 06 3e 05 71 52 22 2c 05 64 0c 04 6e 20 1e 2c 24 00 0a 05 38 05 09 00 6e 20 09 2c 24 00 0c 05 6e 20 4e 2a 53 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}