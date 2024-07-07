
rule Trojan_BAT_SnakeKeylogger_DB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 74 65 73 74 2e 63 6f 2f 74 73 74 } //1 //test.co/tst
		$a_81_1 = {57 65 62 48 65 61 64 65 72 43 6f 6c 6c 65 63 74 69 6f 6e } //1 WebHeaderCollection
		$a_81_2 = {4e 61 6d 65 56 61 6c 75 65 43 6f 6c 6c 65 63 74 69 6f 6e } //1 NameValueCollection
		$a_81_3 = {4d 79 20 54 65 73 74 20 48 65 61 64 65 72 20 56 61 6c 75 65 } //1 My Test Header Value
		$a_81_4 = {46 6f 72 67 6f 74 4d 6f 64 65 6c } //1 ForgotModel
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_6 = {68 65 6c 6c 6f } //1 hello
		$a_81_7 = {77 6f 72 6c 64 } //1 world
		$a_81_8 = {44 69 73 63 6f 72 64 } //1 Discord
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}