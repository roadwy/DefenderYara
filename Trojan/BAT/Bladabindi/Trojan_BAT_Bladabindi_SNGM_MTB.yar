
rule Trojan_BAT_Bladabindi_SNGM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SNGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 69 6b 72 61 6c 67 6f 64 65 63 } //02 00  fikralgodec
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //02 00  StrReverse
		$a_01_2 = {54 6f 42 79 74 65 } //02 00  ToByte
		$a_01_3 = {47 65 74 53 74 72 69 6e 67 } //02 00  GetString
		$a_01_4 = {00 7a 7a 7a 7a 00 } //00 00  稀空z
	condition:
		any of ($a_*)
 
}