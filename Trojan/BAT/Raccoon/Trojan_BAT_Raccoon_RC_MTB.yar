
rule Trojan_BAT_Raccoon_RC_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 09 09 1f 64 30 03 16 2b 01 17 90 09 0e 00 07 07 d8 20 90 01 04 d8 28 90 00 } //01 00 
		$a_01_1 = {56 65 68 69 63 6c 65 20 4d 61 6e 61 67 65 6d 65 6e 74 20 44 61 74 61 62 61 73 65 2e 61 63 63 64 62 } //00 00  Vehicle Management Database.accdb
	condition:
		any of ($a_*)
 
}