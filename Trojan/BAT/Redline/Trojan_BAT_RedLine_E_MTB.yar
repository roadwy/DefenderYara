
rule Trojan_BAT_RedLine_E_MTB{
	meta:
		description = "Trojan:BAT/RedLine.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 53 4d 44 5a 6b 45 4d 66 63 48 58 57 44 54 51 64 44 58 6a 57 68 57 56 49 70 2e 64 6c 6c } //1 dSMDZkEMfcHXWDTQdDXjWhWVIp.dll
		$a_01_1 = {63 66 52 4f 50 66 5a 50 6d 71 53 65 64 48 59 57 51 6a 44 75 58 4c 4e 78 54 63 4b 77 65 } //1 cfROPfZPmqSedHYWQjDuXLNxTcKwe
		$a_01_2 = {45 4c 68 6e 52 46 51 44 6b 42 4a 71 70 48 6f 42 4d 69 45 5a 72 6b 6b 43 43 6e 54 61 52 } //1 ELhnRFQDkBJqpHoBMiEZrkkCCnTaR
		$a_01_3 = {75 5a 4e 47 72 6b 77 71 7a 62 55 52 75 4b 69 44 6a 77 50 75 74 72 61 72 63 52 } //1 uZNGrkwqzbURuKiDjwPutrarcR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}