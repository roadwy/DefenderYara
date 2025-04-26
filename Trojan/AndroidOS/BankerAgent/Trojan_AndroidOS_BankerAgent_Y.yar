
rule Trojan_AndroidOS_BankerAgent_Y{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.Y,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 67 6e 6f 72 65 5f 62 61 74 74 65 72 79 5f 6f 70 74 69 6d 69 73 61 74 69 6f 6e 73 } //2 Ignore_battery_optimisations
		$a_01_1 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 43 61 72 64 } //2 PostDataNodeCard
		$a_01_2 = {52 65 67 69 73 74 65 72 52 65 63 65 69 76 65 72 49 6e 74 65 72 6e 65 74 } //2 RegisterReceiverInternet
		$a_01_3 = {50 6f 73 74 44 61 74 61 4e 6f 64 65 49 6e 73 74 61 6c 6c } //2 PostDataNodeInstall
		$a_01_4 = {52 45 57 44 5f 53 65 6c 65 63 74 } //2 REWD_Select
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}