
rule Trojan_BAT_Formbook_RPG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c 09 13 04 11 04 17 58 0d 09 06 8e 69 32 e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_RPG_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {4a 00 73 00 67 00 69 00 76 00 7a 00 63 00 65 00 2e 00 70 00 6e 00 67 00 } //01 00  Jsgivzce.png
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_3 = {65 00 6e 00 63 00 20 00 59 00 77 00 42 00 74 00 41 00 47 00 51 00 41 00 49 00 41 00 41 00 76 00 41 00 47 00 4d 00 41 00 49 00 41 00 42 00 30 00 41 00 47 00 6b 00 41 00 62 00 51 00 42 00 6c 00 41 00 47 00 38 00 41 00 64 00 51 00 42 00 30 00 41 00 43 00 41 00 41 00 4d 00 51 00 41 00 31 00 41 00 41 00 } //01 00  enc YwBtAGQAIAAvAGMAIAB0AGkAbQBlAG8AdQB0ACAAMQA1AA
		$a_01_4 = {45 00 6d 00 61 00 69 00 6c 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 20 00 50 00 72 00 6f 00 } //01 00  Email Checker Pro
		$a_01_5 = {51 00 67 00 6b 00 6b 00 74 00 65 00 64 00 65 00 7a 00 76 00 6e 00 79 00 7a 00 66 00 6d 00 78 00 6d 00 66 00 64 00 6a 00 78 00 61 00 } //00 00  Qgkktedezvnyzfmxmfdjxa
	condition:
		any of ($a_*)
 
}