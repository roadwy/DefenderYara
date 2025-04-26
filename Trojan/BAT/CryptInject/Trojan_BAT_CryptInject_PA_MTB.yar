
rule Trojan_BAT_CryptInject_PA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 15 d2 13 30 11 15 1e 63 d1 13 15 11 1a 11 0b 91 13 26 11 1a 11 0b ?? ?? ?? ?? ?? ?? ?? ?? 58 61 11 30 61 d2 9c 11 26 13 1e ?? ?? ?? 58 13 0b 11 0b 11 27 32 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_CryptInject_PA_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 00 4e 00 4c 00 49 00 4e 00 45 00 5f 00 4f 00 52 00 44 00 45 00 52 00 5f 00 53 00 48 00 4f 00 50 00 50 00 49 00 4e 00 47 00 5f 00 45 00 43 00 4f 00 4d 00 4d 00 45 00 52 00 43 00 45 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 32 00 34 00 33 00 31 00 } //1 ONLINE_ORDER_SHOPPING_ECOMMERCE_ICON_192431
		$a_81_1 = {61 64 66 61 73 64 61 73 } //1 adfasdas
		$a_81_2 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //1 ResolveSignature
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_4 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //1 get_FullName
		$a_81_5 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}