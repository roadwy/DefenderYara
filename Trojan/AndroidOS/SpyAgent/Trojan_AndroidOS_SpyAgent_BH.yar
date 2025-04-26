
rule Trojan_AndroidOS_SpyAgent_BH{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.BH,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 53 6d 73 41 62 } //1 sendSmsAb
		$a_01_1 = {75 70 6c 6f 61 64 50 68 6f 6e 65 4e 75 6d 62 65 72 73 } //1 uploadPhoneNumbers
		$a_01_2 = {4c 63 6f 6d 2f 74 72 61 6d 2f 6d 6a 2f } //1 Lcom/tram/mj/
		$a_01_3 = {66 69 6c 6c 41 70 70 73 20 70 72 65 66 65 72 65 6e 63 65 73 2e 61 70 70 73 49 6e 73 74 61 6c 6c 65 64 } //1 fillApps preferences.appsInstalled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}