
rule Trojan_BAT_FormBook_KAN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 05 08 6f 90 01 01 00 00 0a 25 26 09 90 00 } //02 00 
		$a_01_1 = {14 14 11 06 } //02 00  ᐔؑ
		$a_01_2 = {25 26 26 1f } //02 00  ☥ἦ
		$a_01_3 = {06 25 26 28 } //02 00  ┆⠦
		$a_03_4 = {70 0a 06 28 90 01 01 00 00 0a 25 26 0b 28 90 01 01 00 00 0a 25 26 07 16 07 8e 69 6f 90 01 01 00 00 0a 25 26 0a 28 90 01 01 00 00 0a 25 26 06 6f 90 01 01 00 00 0a 25 26 0c 90 00 } //01 00 
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_6 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}