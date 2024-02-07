
rule Trojan_BAT_ClipBanker_CXIS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CXIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 68 46 71 57 47 5a 46 63 73 59 73 6b 49 } //01 00  whFqWGZFcsYskI
		$a_01_1 = {6b 44 5a 76 43 75 4b 4f 6b 67 } //01 00  kDZvCuKOkg
		$a_01_2 = {6f 63 76 54 76 48 74 66 55 74 } //01 00  ocvTvHtfUt
		$a_01_3 = {75 51 59 54 6b 45 7a 65 43 6f 47 4b 5a 72 } //01 00  uQYTkEzeCoGKZr
		$a_01_4 = {41 61 41 62 50 4f 4f 72 42 68 64 6a 70 4f } //00 00  AaAbPOOrBhdjpO
	condition:
		any of ($a_*)
 
}