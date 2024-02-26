
rule Trojan_BAT_NjRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {26 08 09 02 09 91 11 04 11 04 06 84 95 11 04 07 84 95 d7 6e 90 01 05 6a 5f b7 95 61 86 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_NjRAT_NR_MTB_2{
	meta:
		description = "Trojan:BAT/NjRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 06 72 10 4a 01 70 28 90 01 03 06 28 90 01 03 0a 28 90 01 03 0a 0b 07 28 90 01 03 0a 0c 08 6f 90 01 03 0a 14 14 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {73 76 63 68 6f 73 74 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //00 00  svchost.My.Resources
	condition:
		any of ($a_*)
 
}