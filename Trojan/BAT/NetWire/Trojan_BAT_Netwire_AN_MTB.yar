
rule Trojan_BAT_Netwire_AN_MTB{
	meta:
		description = "Trojan:BAT/Netwire.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 09 11 0a 6f 90 01 01 00 00 0a 13 0b 2b 19 11 0a 11 09 6f 90 01 01 00 00 0a 0d 08 09 28 90 01 01 00 00 0a d6 0c 11 09 17 d6 13 09 11 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Netwire_AN_MTB_2{
	meta:
		description = "Trojan:BAT/Netwire.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {70 18 8d 17 00 00 01 25 16 72 90 01 03 70 a2 25 17 72 90 01 03 70 a2 14 14 14 28 90 00 } //01 00 
		$a_01_1 = {41 00 63 00 74 00 69 00 6f 00 6e 00 73 00 32 00 45 00 76 00 65 00 6e 00 74 00 73 00 4d 00 61 00 70 00 70 00 69 00 6e 00 67 00 } //01 00  Actions2EventsMapping
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}