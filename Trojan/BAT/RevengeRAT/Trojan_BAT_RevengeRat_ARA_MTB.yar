
rule Trojan_BAT_RevengeRat_ARA_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0b 16 0c 16 13 06 2b 5a 00 07 17 58 20 ff 00 00 00 5f 0b 08 11 04 07 e0 95 58 20 ff 00 00 00 5f 0c 11 04 07 e0 95 0d 11 04 07 e0 11 04 08 e0 95 9e 11 04 08 e0 09 9e 11 05 11 06 02 11 06 91 11 04 11 04 07 e0 95 11 04 08 e0 95 58 20 ff 00 00 00 5f e0 95 61 28 } //00 00 
	condition:
		any of ($a_*)
 
}