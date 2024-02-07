
rule Trojan_BAT_Formbook_FLL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.FLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 69 78 65 6c } //02 00  GetPixel
		$a_01_1 = {54 6f 41 72 72 61 79 } //02 00  ToArray
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_3 = {33 00 2e 00 31 00 31 00 30 00 2e 00 32 00 31 00 36 00 2e 00 36 00 34 00 } //01 00  3.110.216.64
		$a_01_4 = {74 00 69 00 6e 00 79 00 2e 00 6f 00 6e 00 65 00 2f 00 34 00 7a 00 75 00 72 00 79 00 65 00 39 00 62 00 } //01 00  tiny.one/4zurye9b
		$a_01_5 = {32 00 2e 00 35 00 38 00 2e 00 31 00 34 00 39 00 2e 00 32 00 31 00 39 00 } //01 00  2.58.149.219
		$a_01_6 = {78 00 2e 00 72 00 75 00 6e 00 65 00 2d 00 73 00 70 00 65 00 63 00 74 00 72 00 61 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 } //00 00  x.rune-spectrals.com
	condition:
		any of ($a_*)
 
}