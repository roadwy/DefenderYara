
rule Trojan_BAT_Remcos_NEA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 6e 00 64 00 61 00 6c 00 4d 00 61 00 67 00 69 00 63 00 } //01 00  MandalMagic
		$a_01_1 = {24 00 24 00 4e 00 6f 00 42 00 6f 00 64 00 79 00 43 00 61 00 6e 00 47 00 65 00 74 00 49 00 74 00 24 00 24 00 } //01 00  $$NoBodyCanGetIt$$
		$a_01_2 = {24 00 24 00 4d 00 4c 00 4b 00 6a 00 63 00 6c 00 6b 00 64 00 73 00 6a 00 66 00 6b 00 6c 00 73 00 64 00 66 00 6b 00 67 00 68 00 66 00 64 00 6b 00 68 00 67 00 66 00 68 00 6d 00 6a 00 6c 00 79 00 69 00 6c 00 24 00 24 00 } //01 00  $$MLKjclkdsjfklsdfkghfdkhgfhmjlyil$$
		$a_01_3 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //01 00  ASAMethod0ASA
		$a_01_4 = {76 00 4d 00 76 00 65 00 76 00 74 00 76 00 68 00 76 00 6f 00 76 00 64 00 76 00 30 00 76 00 } //00 00  vMvevtvhvovdv0v
	condition:
		any of ($a_*)
 
}