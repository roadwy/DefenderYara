
rule Trojan_BAT_AveMariaRAT_E_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 41 53 4c 4c 4c 4c 4c 4c 4c } //02 00  CASLLLLLLL
		$a_01_1 = {4d 4f 41 4e 4d 5a 41 41 41 41 41 41 41 52 } //02 00  MOANMZAAAAAAAR
		$a_01_2 = {49 6e 73 74 61 6c 6c 52 65 67 69 73 74 72 79 } //00 00  InstallRegistry
	condition:
		any of ($a_*)
 
}