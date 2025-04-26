
rule Trojan_AndroidOS_SpyBanker_AL{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AL,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 61 73 73 61 67 67 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 41 6c 69 61 73 } //2 massagg/MainActivityAlias
		$a_01_1 = {67 6f 6f 67 6c 65 2f 6d 61 73 73 61 67 67 2f 53 65 6e 64 53 4d 53 } //2 google/massagg/SendSMS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}