
rule Trojan_BAT_Raccoon_PSIS_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.PSIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 06 28 6e 00 00 0a 25 26 0b 28 6f 00 00 0a 07 16 07 8e 69 6f 70 00 00 0a 25 26 0a 28 16 00 00 0a 06 6f 1d 00 00 0a 0c 1f 61 6a 08 28 90 00 00 06 25 26 80 31 00 00 04 2a } //00 00 
	condition:
		any of ($a_*)
 
}