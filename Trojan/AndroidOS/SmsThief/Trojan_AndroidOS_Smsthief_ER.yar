
rule Trojan_AndroidOS_Smsthief_ER{
	meta:
		description = "Trojan:AndroidOS/Smsthief.ER,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 31 32 33 34 35 36 38 37 39 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 51 57 45 52 54 59 55 49 4f 50 41 53 44 46 47 48 4a 4b 4c 5a 58 43 56 42 4e 4d } //1 0123456879qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM
		$a_01_1 = {45 6c 65 67 61 6e 74 43 72 79 70 74 6f 44 65 } //1 ElegantCryptoDe
		$a_01_2 = {4b 45 59 5f 4d 41 58 5f 53 4d 53 5f 54 49 4d 45 } //1 KEY_MAX_SMS_TIME
		$a_01_3 = {25 73 2f 58 6d 73 2f 25 73 } //1 %s/Xms/%s
		$a_01_4 = {78 6d 73 55 73 65 72 } //1 xmsUser
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}