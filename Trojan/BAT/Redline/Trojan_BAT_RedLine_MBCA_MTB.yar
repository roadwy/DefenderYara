
rule Trojan_BAT_RedLine_MBCA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 34 02 07 6f 90 01 01 00 00 0a 03 07 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 0c 06 90 00 } //01 00 
		$a_01_1 = {25 16 1f 7c 9d 6f d7 00 00 0a 0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f 60 00 00 06 2c 0c 06 6f 5d 00 00 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7 } //00 00 
	condition:
		any of ($a_*)
 
}