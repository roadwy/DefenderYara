
rule Trojan_BAT_Heracles_SOJ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SOJ!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 61 00 74 00 61 00 4c 00 6f 00 67 00 73 00 5f 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 5f 00 6f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 2e 00 74 00 78 00 74 00 } //1 DataLogs_keylog_offline.txt
		$a_01_1 = {43 00 3a 00 2f 00 2f 00 54 00 65 00 6d 00 70 00 2f 00 2f 00 31 00 2e 00 6c 00 6f 00 67 00 } //1 C://Temp//1.log
		$a_01_2 = {56 00 65 00 6e 00 6f 00 6d 00 52 00 41 00 54 00 42 00 79 00 56 00 65 00 6e 00 6f 00 6d 00 } //1 VenomRATByVenom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}