
rule Trojan_BAT_njRAT_MBBN_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 36 62 01 70 17 18 8d 90 01 01 00 00 01 0d 09 16 72 44 62 01 70 a2 00 09 17 14 a2 00 09 90 00 } //01 00 
		$a_01_1 = {0a 06 72 2c 62 01 70 72 32 62 01 70 17 15 16 } //01 00 
		$a_01_2 = {54 00 56 00 71 00 51 00 25 00 5e 00 25 00 5e 00 4d 00 25 00 5e 00 25 00 5e 00 25 00 5e 00 25 00 5e 00 45 00 25 00 } //00 00  TVqQ%^%^M%^%^%^%^E%
	condition:
		any of ($a_*)
 
}