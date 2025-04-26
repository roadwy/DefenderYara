
rule Trojan_BAT_AgentTesla_NE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 9c 06 17 58 0a 06 08 11 06 17 58 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_NE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 17 da 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 09 11 06 09 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? da 13 07 11 04 11 07 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 11 06 17 d6 13 06 11 06 11 05 31 b9 } //1
		$a_01_1 = {69 00 33 06 6e 00 76 00 33 06 6f 00 6b 00 33 06 65 00 } //1 iسnvسokسe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {48 6f 74 65 6c 4d 67 6d 74 53 79 73 74 65 6d 2e 6c 6f 67 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 HotelMgmtSystem.loginForm.resources
		$a_81_1 = {62 74 6e 49 6e 76 6f 69 63 65 5f 43 6c 69 63 6b } //1 btnInvoice_Click
		$a_81_2 = {74 72 61 6e 73 61 63 74 69 6f 6e 46 6f 72 6d 5f 4c 6f 61 64 } //1 transactionForm_Load
		$a_81_3 = {72 65 63 65 69 70 74 5f 4c 6f 61 64 } //1 receipt_Load
		$a_81_4 = {62 74 6e 4c 6f 67 69 6e 5f 43 6c 69 63 6b } //1 btnLogin_Click
		$a_81_5 = {62 74 6e 50 61 79 5f 43 6c 69 63 6b } //1 btnPay_Click
		$a_81_6 = {42 61 79 77 61 74 63 68 20 56 69 6c 6c 61 73 } //1 Baywatch Villas
		$a_81_7 = {4d 6f 6e 6f 74 79 70 65 20 43 6f 72 73 69 76 61 } //1 Monotype Corsiva
		$a_81_8 = {67 65 74 5f 70 61 73 73 77 6f 72 64 } //1 get_password
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}