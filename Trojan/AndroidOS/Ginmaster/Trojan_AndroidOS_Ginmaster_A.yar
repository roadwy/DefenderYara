
rule Trojan_AndroidOS_Ginmaster_A{
	meta:
		description = "Trojan:AndroidOS/Ginmaster.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 67 61 6d 65 73 6e 73 2f 6d 6f 64 65 6c } //1 Lcom/gamesns/model
		$a_01_1 = {66 69 6e 69 73 68 2c 20 72 65 63 6f 72 64 74 69 6d 65 } //1 finish, recordtime
		$a_01_2 = {53 69 67 6e 20 69 6e 20 74 6f 20 47 61 6d 65 73 6e 73 } //1 Sign in to Gamesns
		$a_01_3 = {63 68 65 63 6b 69 6e 44 65 74 61 69 6c 73 54 65 78 74 } //1 checkinDetailsText
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}