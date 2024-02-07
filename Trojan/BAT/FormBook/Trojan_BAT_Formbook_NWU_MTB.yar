
rule Trojan_BAT_Formbook_NWU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_81_0 = {50 35 33 59 53 43 59 52 42 56 48 48 55 50 38 47 34 37 42 37 35 59 } //01 00  P53YSCYRBVHHUP8G47B75Y
		$a_81_1 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //01 00  System.Reflection.Assembly
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}