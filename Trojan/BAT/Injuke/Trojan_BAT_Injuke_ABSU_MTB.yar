
rule Trojan_BAT_Injuke_ABSU_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ABSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_1 = {52 65 76 65 72 73 65 } //03 00  Reverse
		$a_01_2 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 } //00 00 
	condition:
		any of ($a_*)
 
}