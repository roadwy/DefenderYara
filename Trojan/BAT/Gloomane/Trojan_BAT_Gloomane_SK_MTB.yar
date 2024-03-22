
rule Trojan_BAT_Gloomane_SK_MTB{
	meta:
		description = "Trojan:BAT/Gloomane.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {34 34 20 43 41 4c 49 42 45 52 } //02 00  44 CALIBER
		$a_01_1 = {49 6e 73 69 64 69 6f 75 73 2e 65 78 65 } //02 00  Insidious.exe
		$a_01_2 = {46 75 63 6b 54 68 65 53 79 73 74 65 6d 20 43 6f 70 79 72 69 67 68 74 } //00 00  FuckTheSystem Copyright
	condition:
		any of ($a_*)
 
}