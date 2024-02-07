
rule Trojan_BAT_AveMaria_NEAJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 61 76 69 73 31 31 2e 46 6f 72 6d 42 61 73 65 2e 72 65 73 6f 75 72 63 65 73 } //05 00  Davis11.FormBase.resources
		$a_01_1 = {55 56 6d 56 77 36 } //05 00  UVmVw6
		$a_01_2 = {61 7a 68 61 6e 73 } //05 00  azhans
		$a_01_3 = {59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 00 } //03 00  Y5tFvU8EY
		$a_01_4 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //03 00  get_KeyCode
		$a_01_5 = {67 65 74 5f 73 6f 72 63 65 63 69 74 79 } //03 00  get_sorcecity
		$a_01_6 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //03 00  get_Password
		$a_01_7 = {67 65 74 5f 49 73 6c 65 54 6f 70 4c } //02 00  get_IsleTopL
		$a_01_8 = {43 52 55 44 70 65 72 73 6f 6e 65 6c 73 5f 44 4c 4c } //00 00  CRUDpersonels_DLL
	condition:
		any of ($a_*)
 
}