
rule Trojan_BAT_Remcos_ZA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 70 61 6e 65 6c 4d 49 53 } //01 00  get_panelMIS
		$a_01_1 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //01 00  add_Shutdown
		$a_01_2 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 75 63 55 73 65 72 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Lerlibro_INC.ucUsers.resources
		$a_01_3 = {24 31 31 31 61 64 30 32 62 2d 63 63 63 64 2d 34 31 30 36 2d 62 33 32 38 2d 39 33 62 33 61 64 62 30 35 65 35 32 } //01 00  $111ad02b-cccd-4106-b328-93b3adb05e52
		$a_01_4 = {74 78 74 50 61 73 73 77 6f 72 64 } //00 00  txtPassword
	condition:
		any of ($a_*)
 
}