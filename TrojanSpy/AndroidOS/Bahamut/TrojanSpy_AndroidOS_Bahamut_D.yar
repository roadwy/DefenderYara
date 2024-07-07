
rule TrojanSpy_AndroidOS_Bahamut_D{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 6d 73 41 6c 6c 42 72 6f 61 64 43 61 73 74 } //2 SmsAllBroadCast
		$a_01_1 = {4b 26 4d 39 42 23 29 4f 2f 52 5c 3d 50 25 68 41 } //2 K&M9B#)O/R\=P%hA
		$a_00_2 = {63 6f 6d 2e 67 72 65 65 6e 66 6c 61 67 2e 73 79 73 74 65 6d } //1 com.greenflag.system
		$a_00_3 = {63 6f 6d 2e 66 6f 72 73 2e 61 70 70 73 } //1 com.fors.apps
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}