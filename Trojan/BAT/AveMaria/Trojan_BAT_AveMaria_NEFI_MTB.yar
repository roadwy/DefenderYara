
rule Trojan_BAT_AveMaria_NEFI_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {63 33 64 36 31 37 36 65 2d 34 39 30 64 2d 34 35 37 38 2d 38 30 36 61 2d 30 39 37 35 34 62 34 62 33 38 36 36 } //02 00  c3d6176e-490d-4578-806a-09754b4b3866
		$a_01_1 = {53 61 66 65 47 61 6d 65 57 69 6e 46 6f 72 6d 73 } //02 00  SafeGameWinForms
		$a_01_2 = {4c 61 62 32 5f 41 6e 61 67 72 61 6d 2e 66 72 6d 4d 61 69 6e 57 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Lab2_Anagram.frmMainWindow.resources
	condition:
		any of ($a_*)
 
}