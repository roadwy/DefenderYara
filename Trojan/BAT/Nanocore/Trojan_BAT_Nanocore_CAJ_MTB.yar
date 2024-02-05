
rule Trojan_BAT_Nanocore_CAJ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {26 2b 32 11 04 11 05 02 11 05 91 06 61 08 09 91 61 b4 9c 09 16 2d 12 03 6f 90 01 01 00 00 0a 17 da 33 07 16 16 2c 59 26 2b 07 09 17 25 2c c0 d6 0d 11 05 17 d6 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}