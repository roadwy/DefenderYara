
rule Trojan_BAT_SpyNoon_NZQ_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.NZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 09 17 6f 90 01 01 00 00 0a 11 0a 91 61 9c 11 0a 17 d6 13 0a 11 0a 11 09 31 cb 90 00 } //01 00 
		$a_81_1 = {4b 65 6e 50 68 61 73 46 75 63 6b 65 64 6b 73 61 6a 64 34 34 } //01 00  KenPhasFuckedksajd44
		$a_81_2 = {63 63 2f 4b 46 32 62 44 31 54 4d 2f 73 74 6f 63 6b } //00 00  cc/KF2bD1TM/stock
	condition:
		any of ($a_*)
 
}