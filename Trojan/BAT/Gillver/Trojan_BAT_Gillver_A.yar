
rule Trojan_BAT_Gillver_A{
	meta:
		description = "Trojan:BAT/Gillver.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 00 75 00 6e 00 50 00 45 00 90 01 02 49 00 6e 00 6a 00 65 00 63 00 74 00 50 00 45 00 90 00 } //01 00 
		$a_01_1 = {50 6f 6c 79 44 65 43 72 79 70 74 } //01 00  PolyDeCrypt
		$a_01_2 = {74 00 72 00 6f 00 6c 00 6f 00 6c 00 6f 00 6c 00 6f 00 6c 00 } //00 00  trolololol
	condition:
		any of ($a_*)
 
}