
rule Trojan_AndroidOS_BankBot_B_MTB{
	meta:
		description = "Trojan:AndroidOS/BankBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 75 73 70 65 63 74 20 61 20 44 6f 53 20 61 74 74 61 63 6b 20 62 61 73 65 64 20 6f 6e 20 68 61 73 68 20 63 6f 6c 6c 69 73 69 6f 6e 73 } //01 00 
		$a_00_1 = {72 65 71 75 69 72 65 69 6e 6a 65 63 74 } //01 00 
		$a_00_2 = {66 61 73 74 65 72 78 6d 6c 2f 6a 61 63 6b 73 6f 6e 2f 63 6f 72 65 2f 6a 73 6f 6e 2f 42 79 74 65 53 6f 75 72 63 65 4a 73 6f 6e 42 6f 6f 74 73 74 72 61 70 70 65 72 } //01 00 
		$a_00_3 = {67 65 74 53 6e 61 70 73 68 6f 74 } //01 00 
		$a_00_4 = {72 65 63 6f 6d 6d 65 6e 64 65 64 5f 63 61 72 64 5f 76 69 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}