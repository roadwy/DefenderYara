
rule TrojanSpy_AndroidOS_Bahamut_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 44 75 72 61 74 69 6f 6e 2d 2d 00 0e 20 2c 20 43 61 6c 6c 20 54 79 70 65 2d 2d 00 0f 20 2c 20 43 61 6c 6c 65 72 4e 61 6d 65 2d 2d 00 } //2
		$a_00_1 = {1d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 3e 0a 20 44 65 76 69 63 65 20 49 6e 66 6f 20 20 3a 20 00 } //1
		$a_00_2 = {2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 3e 3e 0a 4d 65 73 73 61 67 65 73 20 } //1
		$a_00_3 = {50 68 6f 6e 65 4e 75 6d 62 65 72 20 2d 2d } //1 PhoneNumber --
		$a_00_4 = {4d 65 64 69 61 46 69 6c 65 00 } //1 敍楤䙡汩e
		$a_00_5 = {43 61 6c 6c 48 69 73 74 6f 72 79 00 } //1 慃汬楈瑳牯y
		$a_00_6 = {42 6c 6f 77 66 69 73 68 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}