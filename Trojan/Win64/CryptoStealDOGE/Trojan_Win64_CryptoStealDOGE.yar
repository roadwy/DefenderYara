
rule Trojan_Win64_CryptoStealDOGE{
	meta:
		description = "Trojan:Win64/CryptoStealDOGE,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 39 00 58 00 71 00 38 00 53 00 4a 00 4b 00 36 00 79 00 31 00 4d 00 47 00 35 00 57 00 74 00 38 00 41 00 71 00 61 00 72 00 69 00 64 00 6e 00 46 00 46 00 6d 00 42 00 69 00 63 00 57 00 62 00 67 00 77 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CryptoStealDOGE_2{
	meta:
		description = "Trojan:Win64/CryptoStealDOGE,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 42 00 4b 00 51 00 4a 00 6d 00 6b 00 79 00 6b 00 54 00 74 00 6e 00 31 00 6a 00 37 00 42 00 34 00 64 00 6e 00 75 00 33 00 74 00 50 00 45 00 74 00 35 00 4a 00 7a 00 78 00 55 00 33 00 4e 00 67 00 4e 00 } //00 00 
	condition:
		any of ($a_*)
 
}