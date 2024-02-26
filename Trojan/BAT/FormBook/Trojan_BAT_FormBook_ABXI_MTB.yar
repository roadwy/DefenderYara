
rule Trojan_BAT_FormBook_ABXI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {02 1c 1d 2d 0d 26 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 2b 03 26 2b f1 2a 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00  ReadAsByteArrayAsync
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}