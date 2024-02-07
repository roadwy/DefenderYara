
rule Trojan_BAT_NjRAT_NA_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 9a 18 9a 6f 90 01 01 00 00 0a 74 90 01 01 00 00 1b 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 06 07 9a 19 9a 0d 28 90 01 01 00 00 0a 09 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 7e 90 01 01 00 00 04 0d 28 90 01 01 00 00 0a 09 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2c 07 90 00 } //01 00 
		$a_01_1 = {6a 64 6a 7a 70 6e 6e 72 73 6c 6a 77 71 74 76 78 2e 52 65 73 6f 75 72 63 65 73 } //00 00  jdjzpnnrsljwqtvx.Resources
	condition:
		any of ($a_*)
 
}