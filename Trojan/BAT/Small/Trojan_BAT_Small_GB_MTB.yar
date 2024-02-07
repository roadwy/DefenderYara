
rule Trojan_BAT_Small_GB_MTB{
	meta:
		description = "Trojan:BAT/Small.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {28 1c 00 00 0a 20 08 00 00 00 38 68 ff ff ff 28 13 00 00 0a 20 08 00 00 00 28 1d 00 00 06 6f 14 00 00 0a 3a 08 ff ff ff 20 00 00 00 00 fe 0e 02 00 28 04 00 00 06 3a 38 ff ff ff 07 73 1d 00 00 0a 25 16 6f 1e 00 00 0a 6f 1f 00 00 0a 20 06 00 00 00 fe 0e 02 00 28 04 00 00 06 39 b0 fe ff ff 38 0e ff ff ff } //01 00 
		$a_81_1 = {42 69 74 63 6f 69 6e 5f 47 72 61 62 62 65 72 } //01 00  Bitcoin_Grabber
		$a_81_2 = {6f 35 78 30 52 36 75 46 66 5a 51 68 72 45 32 39 4d 63 } //01 00  o5x0R6uFfZQhrE29Mc
		$a_81_3 = {52 77 33 6e 36 45 5a 49 57 33 58 58 53 77 52 4c 4e 4e } //00 00  Rw3n6EZIW3XXSwRLNN
	condition:
		any of ($a_*)
 
}