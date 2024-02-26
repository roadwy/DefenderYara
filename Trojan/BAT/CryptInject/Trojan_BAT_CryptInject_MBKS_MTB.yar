
rule Trojan_BAT_CryptInject_MBKS_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 07 6f 90 01 01 00 00 0a 00 09 04 6f 90 01 01 00 00 0a 00 09 05 6f 90 01 01 00 00 0a 00 09 6f 90 01 01 00 00 0a 13 04 11 04 02 16 02 8e 69 90 00 } //01 00 
		$a_01_1 = {67 00 74 00 73 00 61 00 76 00 6a 00 76 00 45 00 52 00 41 00 63 00 77 00 6b 00 6f 00 47 00 34 00 6d 00 30 00 46 00 68 00 67 00 42 00 53 00 46 00 58 00 5a 00 66 00 66 00 6d 00 42 00 4b 00 49 00 73 00 6b 00 4a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CryptInject_MBKS_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 5e 00 41 00 44 00 5e 00 5e 00 41 00 5f 00 5e 00 5e 00 41 00 50 00 37 00 37 00 59 00 5e 00 43 00 34 00 5e 00 5e 00 5e 00 5e 00 5e 00 41 00 43 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e 00 5e } //01 00 
		$a_01_1 = {20 00 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 4c 00 75 00 75 00 4e 00 69 00 65 00 6d 00 2e 00 43 00 6f 00 75 00 70 00 6f 00 6e 00 4e 00 75 00 6d 00 62 00 65 00 72 00 20 } //00 00 
	condition:
		any of ($a_*)
 
}