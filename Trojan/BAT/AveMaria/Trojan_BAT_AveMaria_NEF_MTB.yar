
rule Trojan_BAT_AveMaria_NEF_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 63 7a 64 76 73 64 73 64 76 66 63 64 73 61 73 64 63 65 73 73 } //01 00  Suczdvsdsdvfcdsasdcess
		$a_01_1 = {46 61 69 6c 67 64 66 73 64 61 63 73 64 64 67 68 64 73 68 73 64 68 42 65 67 69 6e } //01 00  FailgdfsdacsddghdshsdhBegin
		$a_01_2 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //01 00  ObfuscatedByGoliath
		$a_01_3 = {49 76 61 6e 20 4d 65 65 64 65 76 } //01 00  Ivan Meedev
		$a_01_4 = {43 00 3a 00 5c 00 54 00 65 00 66 00 73 00 64 00 73 00 73 00 64 00 64 00 64 00 64 00 6d 00 70 00 } //01 00  C:\Tefsdssddddmp
		$a_01_5 = {43 00 3a 00 5c 00 4e 00 65 00 64 00 64 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 64 00 77 00 54 00 65 00 6d 00 70 00 } //00 00  C:\NeddssssssssssssssddddddddddddddddddddwTemp
	condition:
		any of ($a_*)
 
}