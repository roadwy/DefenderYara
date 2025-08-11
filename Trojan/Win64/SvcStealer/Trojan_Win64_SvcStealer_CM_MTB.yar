
rule Trojan_Win64_SvcStealer_CM_MTB{
	meta:
		description = "Trojan:Win64/SvcStealer.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_81_0 = {39 41 50 41 52 57 38 33 5a 36 } //2 9APARW83Z6
		$a_81_1 = {36 32 2e 36 30 2e 32 32 36 2e 31 39 31 } //2 62.60.226.191
		$a_81_2 = {75 69 64 3d 25 73 26 76 65 72 3d 25 73 } //1 uid=%s&ver=%s
		$a_81_3 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 } //1 SELECT name_on_card, expiration_month, expiration_year, card_numb
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}