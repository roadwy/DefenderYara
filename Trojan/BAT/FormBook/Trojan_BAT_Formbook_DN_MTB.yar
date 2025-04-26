
rule Trojan_BAT_Formbook_DN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {6d 69 6c 65 73 74 6f 6e 65 32 2e 52 65 73 6f 75 72 63 65 73 } //1 milestone2.Resources
		$a_81_1 = {67 72 6f 75 70 34 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 group4ConnectionString
		$a_81_2 = {67 65 74 5f 43 6f 6e 6e 65 63 74 69 6f 6e } //1 get_Connection
		$a_81_3 = {53 70 6c 61 73 68 53 63 72 65 65 6e } //1 SplashScreen
		$a_81_4 = {43 61 73 68 69 65 72 } //1 Cashier
		$a_81_5 = {42 75 74 63 68 65 72 79 } //1 Butchery
		$a_81_6 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //1 smtp.gmail.com
		$a_81_7 = {4c 6f 63 6b 48 6f 6c 64 65 72 } //1 LockHolder
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}