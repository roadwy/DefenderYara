
rule Trojan_Win32_Visero_A{
	meta:
		description = "Trojan:Win32/Visero.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 50 52 45 41 44 5f 53 4b 59 50 45 } //01 00  SPREAD_SKYPE
		$a_01_1 = {44 44 4f 53 5f 53 49 4d 50 4c 45 } //01 00  DDOS_SIMPLE
		$a_01_2 = {25 2c 42 44 4f 57 4e 4c 4f 41 44 45 52 5f 55 52 4c } //01 00  %,BDOWNLOADER_URL
		$a_01_3 = {42 69 74 74 65 20 61 6b 74 75 61 6c 69 73 69 65 72 65 6e 20 53 69 65 20 49 68 72 65 20 5a 61 68 6c 75 6e 67 73 64 61 74 65 6e } //00 00  Bitte aktualisieren Sie Ihre Zahlungsdaten
	condition:
		any of ($a_*)
 
}