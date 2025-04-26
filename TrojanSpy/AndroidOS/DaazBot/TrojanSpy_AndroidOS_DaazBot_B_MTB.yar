
rule TrojanSpy_AndroidOS_DaazBot_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DaazBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 69 74 63 6f 6e 63 65 4c 6f 67 73 2e 63 73 76 } //1 bitconceLogs.csv
		$a_01_1 = {62 69 74 63 6f 6e 63 65 4c 6f 67 73 2e 7a 69 70 } //1 bitconceLogs.zip
		$a_01_2 = {42 61 6e 6b 53 6d 73 44 6f 6d 61 69 6e } //1 BankSmsDomain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}