
rule Trojan_BAT_FormBook_ABJF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de } //5
		$a_01_1 = {50 00 72 00 65 00 64 00 69 00 63 00 74 00 69 00 6f 00 6e 00 53 00 63 00 6f 00 72 00 65 00 72 00 2e 00 52 00 58 00 41 00 51 00 51 00 51 00 51 00 } //1 PredictionScorer.RXAQQQQ
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}