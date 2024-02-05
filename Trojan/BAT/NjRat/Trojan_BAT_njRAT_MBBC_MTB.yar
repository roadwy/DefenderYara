
rule Trojan_BAT_njRAT_MBBC_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 07 09 16 6f 90 01 01 00 00 0a 13 04 12 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 17 d6 0d 09 08 31 dd 90 00 } //01 00 
		$a_01_1 = {30 63 64 37 66 61 36 31 64 30 34 64 } //01 00 
		$a_01_2 = {6c 00 69 00 6e 00 6b 00 70 00 69 00 63 00 74 00 75 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 71 00 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}