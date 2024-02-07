
rule Trojan_BAT_CryptInject_NW_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 66 64 61 73 73 73 73 73 73 73 73 73 73 64 66 66 64 64 6c 65 74 65 64 } //01 00  dfdassssssssssdffddleted
		$a_81_1 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //01 00  System.Reflection.Emit
		$a_81_2 = {68 50 66 64 73 66 68 64 73 64 72 6f 64 73 63 65 73 73 } //01 00  hPfdsfhdsdrodscess
		$a_81_3 = {6c 70 66 73 64 66 41 66 64 73 64 64 73 61 64 72 65 73 73 } //01 00  lpfsdfAfdsddsadress
		$a_81_4 = {66 6c 50 72 6f 64 73 64 74 64 73 66 61 65 66 64 73 63 74 } //01 00  flProdsdtdsfaefdsct
		$a_81_5 = {66 61 67 66 64 67 64 61 73 } //01 00  fagfdgdas
		$a_81_6 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_81_7 = {44 79 6e 61 6d 69 63 44 6c 6c 49 6e 76 6f 6b 65 54 79 70 65 } //01 00  DynamicDllInvokeType
		$a_81_8 = {46 73 64 66 73 64 66 } //01 00  Fsdfsdf
		$a_81_9 = {66 66 73 64 66 73 64 66 64 73 } //00 00  ffsdfsdfds
	condition:
		any of ($a_*)
 
}