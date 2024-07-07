
rule Trojan_AndroidOS_BrowBot_B{
	meta:
		description = "Trojan:AndroidOS/BrowBot.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 6e 65 74 63 6f 6d 2e 63 6f 6d 2f 64 61 74 61 } //2 apinetcom.com/data
		$a_01_1 = {61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } //2 a8p.net/tqfXDn
		$a_01_2 = {73 6f 75 72 63 65 7a 5f 31 35 } //2 sourcez_15
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_AndroidOS_BrowBot_B_2{
	meta:
		description = "Trojan:AndroidOS/BrowBot.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } //1 https://a8p.net/tqfXDn
		$a_01_1 = {24 44 65 76 69 63 65 4d 6f 64 65 6c 5f 31 36 } //1 $DeviceModel_16
		$a_01_2 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f 31 36 } //1 senderphone_16
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}