
rule Trojan_BAT_DCRat_ARA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 00 44 00 52 00 41 00 54 00 5d 00 } //2 [DRAT]
		$a_01_1 = {47 00 45 00 54 00 5f 00 49 00 4e 00 46 00 4f 00 } //2 GET_INFO
		$a_01_2 = {53 00 45 00 4e 00 54 00 5f 00 49 00 4e 00 46 00 4f 00 } //2 SENT_INFO
		$a_01_3 = {53 00 45 00 4e 00 54 00 5f 00 53 00 4d 00 53 00 } //2 SENT_SMS
		$a_01_4 = {53 00 45 00 4e 00 54 00 5f 00 44 00 49 00 53 00 } //2 SENT_DIS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}