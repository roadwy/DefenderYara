
rule Backdoor_BAT_RevengeRat_YAY_MTB{
	meta:
		description = "Backdoor:BAT/RevengeRat.YAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 06 09 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 02 16 02 8e b7 6f 90 01 03 0a 13 04 11 04 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}