
rule Trojan_BAT_Fanny_X_MTB{
	meta:
		description = "Trojan:BAT/Fanny.X!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 42 4c 4e 4b } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4a 73 } //01 00 
		$a_01_2 = {49 6e 66 65 63 74 } //01 00 
		$a_01_3 = {43 68 65 63 6b 42 6c 61 63 6b 6c 69 73 74 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 4c 6e 6b } //01 00 
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_6 = {62 69 6e 66 6e 61 6d 65 } //00 00 
		$a_01_7 = {00 5d 04 00 00 } //6e 55 
	condition:
		any of ($a_*)
 
}