
rule TrojanSpy_AndroidOS_SMSSpy_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 75 61 70 6b 73 2e 6f 6e 6c 69 6e 65 } //1 muapks.online
		$a_00_1 = {67 72 61 62 73 61 70 6b 73 2e 6f 6e 6c 69 6e 65 } //1 grabsapks.online
		$a_00_2 = {61 70 69 5f 73 70 61 32 34 31 32 35 2f 61 70 69 5f 65 73 70 61 6e 6f 6c 2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //2 api_spa24125/api_espanol/api.php?sid=%1$s&sms=%2$s
		$a_03_3 = {61 70 70 5f 61 62 63 37 37 31 5f 32 73 66 61 63 73 6c 66 66 66 63 73 32 2f 90 02 30 5f 38 38 38 61 2f 64 6c 2e 70 68 70 90 00 } //2
		$a_03_4 = {63 6f 6d 2f 90 02 07 2f 90 02 15 2f 4d 79 52 65 63 90 02 02 76 65 72 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*1) >=5
 
}