
rule Trojan_BAT_CryptMiner_NZK_MTB{
	meta:
		description = "Trojan:BAT/CryptMiner.NZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 2f 00 } //03 00 
		$a_01_1 = {61 66 61 38 2d 33 61 39 64 34 34 33 30 64 63 63 31 } //03 00 
		$a_01_2 = {55 02 c0 09 00 00 00 00 fa 25 33 00 16 00 00 01 } //01 00 
		$a_01_3 = {44 65 63 6f 64 69 6e 67 42 79 74 65 73 } //01 00 
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}