
rule Trojan_Win32_Brontok_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Brontok.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 62 00 74 00 6c 00 6c 00 6a 00 6d 00 6d 00 41 00 50 00 67 00 41 00 50 00 6a 00 6e 00 41 00 } //01 00  ubtlljmmAPgAPjnA
		$a_01_1 = {64 00 70 00 6e 00 71 00 76 00 75 00 66 00 73 00 6f 00 62 00 6e 00 66 00 } //01 00  dpnqvufsobnf
		$a_01_2 = {53 01 52 00 53 00 62 00 63 00 54 00 55 00 64 00 65 00 4e 00 56 00 57 00 66 00 67 00 4e 00 58 00 59 00 62 00 63 00 4e 00 5a 00 52 00 62 00 63 00 64 00 52 00 52 00 53 00 65 00 66 00 67 00 68 00 7e 01 } //00 00  œRSbcTUdeNVWfgNXYbcNZRbcdRRSefghž
	condition:
		any of ($a_*)
 
}