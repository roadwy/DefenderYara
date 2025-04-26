
rule Trojan_BAT_FormBook_NJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 6a 61 d2 9c 00 11 0d 17 6a 58 13 0d 11 0d 11 07 8e 69 17 59 } //5
		$a_81_1 = {74 65 6d 70 75 72 69 2e 6f 72 67 2f 44 61 74 61 53 65 74 } //1 tempuri.org/DataSet
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}
rule Trojan_BAT_FormBook_NJ_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 06 18 d8 1f 18 30 05 06 18 d8 2b 02 1f 18 0a 00 06 1f 18 5d 16 fe 01 0c 08 2c e4 } //5
		$a_81_1 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_2 = {43 72 65 64 69 74 43 61 72 64 4e 75 6d 62 65 72 } //1 CreditCardNumber
		$a_81_3 = {43 72 65 64 69 74 43 61 72 64 43 76 76 } //1 CreditCardCvv
		$a_81_4 = {42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //1 BitcoinAddress
		$a_81_5 = {45 74 68 65 72 65 75 6d 41 64 64 72 65 73 73 } //1 EthereumAddress
		$a_81_6 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=11
 
}