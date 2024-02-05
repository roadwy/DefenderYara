
rule Trojan_BAT_Disstl_ASD_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {49 59 4b 5a 47 32 4e 55 31 31 4d 49 4b 50 31 4e 4b 54 52 53 42 53 5a 57 36 30 } //IYKZG2NU11MIKP1NKTRSBSZW60  03 00 
		$a_80_1 = {47 33 32 38 49 53 4b 46 44 45 42 48 36 54 41 4f 4a 46 49 5a } //G328ISKFDEBH6TAOJFIZ  03 00 
		$a_80_2 = {4d 34 5a 35 4d 42 39 54 47 55 52 50 32 46 52 5a 50 5a 49 32 } //M4Z5MB9TGURP2FRZPZI2  03 00 
		$a_80_3 = {65 6d 61 6e 72 65 73 75 } //emanresu  03 00 
		$a_80_4 = {64 69 73 63 6f 72 64 } //discord  03 00 
		$a_80_5 = {62 64 6c 65 76 65 6c 5c 65 67 61 72 6f 74 53 20 6c 61 63 6f 4c 5c 64 72 6f 63 73 69 64 } //bdlevel\egarotS lacoL\drocsid  03 00 
		$a_80_6 = {47 65 74 41 63 63 65 73 73 43 6f 6e 74 72 6f 6c } //GetAccessControl  00 00 
	condition:
		any of ($a_*)
 
}