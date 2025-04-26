
rule Trojan_AndroidOS_SpyAgent_O{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 52 49 4d 41 52 59 5f 41 43 43 45 53 53 54 4f 4b 45 4e } //2 PRIMARY_ACCESSTOKEN
		$a_00_1 = {50 4c 55 47 49 4e 44 45 58 44 4f 57 4e } //2 PLUGINDEXDOWN
		$a_00_2 = {77 65 63 6f 69 6e 2f 75 70 64 61 74 65 53 74 61 74 65 53 65 72 76 69 63 65 } //2 wecoin/updateStateService
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}