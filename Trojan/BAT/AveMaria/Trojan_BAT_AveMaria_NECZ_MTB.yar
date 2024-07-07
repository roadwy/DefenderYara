
rule Trojan_BAT_AveMaria_NECZ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 07 11 08 9a 1f 10 28 4e 00 00 0a 6f 4f 00 00 0a 00 11 08 17 58 13 08 11 08 20 00 ea 00 00 fe 04 13 09 11 09 2d d9 28 50 00 00 0a 08 6f 51 00 00 0a 6f 52 00 00 0a 0d 09 } //10
		$a_01_1 = {46 61 6d 69 6c 79 42 75 64 67 65 74 4d 61 6e 61 67 65 6d 65 6e 74 } //5 FamilyBudgetManagement
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}