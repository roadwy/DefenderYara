
rule Trojan_BAT_Netwire_AGX_MTB{
	meta:
		description = "Trojan:BAT/Netwire.AGX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 36 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 17 13 04 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {69 00 6e 00 74 00 65 00 6c 00 32 00 32 00 } //01 00  intel22
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {44 00 6e 00 73 00 52 00 69 00 70 00 } //00 00  DnsRip
	condition:
		any of ($a_*)
 
}