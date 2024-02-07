
rule Trojan_BAT_Netwire_AIFT_MTB{
	meta:
		description = "Trojan:BAT/Netwire.AIFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 49 00 16 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {47 00 65 00 74 00 50 00 69 00 78 00 65 00 6c 00 } //01 00  GetPixel
		$a_01_2 = {43 00 61 00 72 00 67 00 6f 00 57 00 69 00 73 00 65 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //01 00  CargoWise.White
		$a_01_3 = {49 00 6e 00 74 00 65 00 6c 00 52 00 65 00 61 00 64 00 65 00 72 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //00 00  IntelReaderLibrary
	condition:
		any of ($a_*)
 
}