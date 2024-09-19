
rule Trojan_AndroidOS_Soumnibot_UT{
	meta:
		description = "Trojan:AndroidOS/Soumnibot.UT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 34 39 2e 31 30 32 2e 32 34 33 2e 31 35 37 3a 38 30 37 37 } //1 http://149.102.243.157:8077
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 37 32 2e 32 34 37 2e 33 39 2e 31 35 34 } //1 http://172.247.39.154
		$a_01_2 = {68 74 74 70 3a 2f 2f 38 39 2e 31 38 37 2e 31 38 34 2e 32 31 33 } //1 http://89.187.184.213
		$a_01_3 = {68 61 6e 64 6c 65 4d 65 73 73 61 67 65 20 73 74 61 72 74 53 65 72 76 69 63 65 } //1 handleMessage startService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}