
rule Trojan_BAT_Netwire_YZS_MTB{
	meta:
		description = "Trojan:BAT/Netwire.YZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8e b7 17 da 11 05 da 02 11 05 91 } //01 00 
		$a_01_1 = {61 8c 15 00 00 01 } //01 00 
		$a_01_2 = {17 8d 03 00 00 01 13 08 11 08 16 } //01 00 
		$a_03_3 = {8c 17 00 00 01 a2 11 08 14 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}