
rule Trojan_BAT_FormBook_KXFA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.KXFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 19 8d 10 00 00 01 25 16 09 a2 25 17 16 8c 90 01 03 01 a2 25 18 11 05 8c 90 01 03 01 a2 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //01 00  CompressionMode
		$a_01_3 = {47 00 34 00 47 00 31 00 35 00 } //00 00  G4G15
	condition:
		any of ($a_*)
 
}