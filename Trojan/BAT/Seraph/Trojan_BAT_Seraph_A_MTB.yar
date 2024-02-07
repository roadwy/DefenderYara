
rule Trojan_BAT_Seraph_A_MTB{
	meta:
		description = "Trojan:BAT/Seraph.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 4f 47 47 59 2e 65 78 65 } //01 00  DOGGY.exe
		$a_81_1 = {4e 62 6f 68 71 78 7a 69 73 6a 72 67 77 7a 66 6e 7a 64 71 65 73 6c 62 79 } //01 00  Nbohqxzisjrgwzfnzdqeslby
		$a_81_2 = {63 6f 6e 6e 65 63 74 69 6f 6e } //01 00  connection
		$a_81_3 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  System.Security.Cryptography
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_5 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //01 00  set_KeySize
		$a_81_6 = {67 65 74 5f 4b 65 79 53 69 7a 65 } //00 00  get_KeySize
	condition:
		any of ($a_*)
 
}