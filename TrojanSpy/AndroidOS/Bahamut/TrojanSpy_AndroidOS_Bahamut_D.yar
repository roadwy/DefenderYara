
rule TrojanSpy_AndroidOS_Bahamut_D{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.D,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 6d 73 41 6c 6c 42 72 6f 61 64 43 61 73 74 } //02 00  SmsAllBroadCast
		$a_01_1 = {4b 26 4d 39 42 23 29 4f 2f 52 5c 3d 50 25 68 41 } //01 00  K&M9B#)O/R\=P%hA
		$a_00_2 = {63 6f 6d 2e 67 72 65 65 6e 66 6c 61 67 2e 73 79 73 74 65 6d } //01 00  com.greenflag.system
		$a_00_3 = {63 6f 6d 2e 66 6f 72 73 2e 61 70 70 73 } //00 00  com.fors.apps
		$a_00_4 = {5d 04 00 00 } //ff a4 
	condition:
		any of ($a_*)
 
}