
rule TrojanDropper_Win32_Strumapine_A{
	meta:
		description = "TrojanDropper:Win32/Strumapine.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 61 00 2e 00 76 00 62 00 65 00 } //01 00  \a.vbe
		$a_01_1 = {43 00 6f 00 6e 00 66 00 69 00 67 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 50 00 6f 00 6c 00 69 00 63 00 79 00 2e 00 65 00 78 00 65 00 6e 00 61 00 6d 00 65 00 } //01 00  ConfigSecurityPolicy.exename
		$a_01_2 = {50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 5f 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 6e 00 61 00 6d 00 65 00 } //01 00  ProtectionManagement_Uninstall.exename
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 2d 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 73 00 2f 00 61 00 2f 00 74 00 72 00 2f 00 6b 00 61 00 74 00 69 00 61 00 2e 00 72 00 61 00 72 00 } //01 00  http://e-defender.com.br/includes/a/tr/katia.rar
		$a_03_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 90 02 60 2f 00 64 00 64 00 2f 00 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 6b 
	condition:
		any of ($a_*)
 
}