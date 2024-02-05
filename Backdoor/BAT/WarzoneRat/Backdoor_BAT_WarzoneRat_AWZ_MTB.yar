
rule Backdoor_BAT_WarzoneRat_AWZ_MTB{
	meta:
		description = "Backdoor:BAT/WarzoneRat.AWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {17 59 0c 2b 1c 00 07 06 08 6f 90 01 03 0a 0d 12 03 28 90 01 03 0a 28 90 01 03 0a 0b 08 17 59 0c 00 08 15 fe 01 16 fe 01 13 04 11 04 2d d7 90 00 } //01 00 
		$a_01_1 = {4e 69 61 6c 6f 6e 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}