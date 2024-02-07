
rule Trojan_BAT_Injuke_AAOA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {08 11 08 17 8d 90 01 01 00 00 01 25 16 07 11 08 9a 1f 10 28 90 01 01 00 00 0a 9c 90 00 } //01 00 
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 00 } //01 00  DeleteMC
		$a_01_2 = {4c 00 6f 00 2d 00 61 00 64 00 } //00 00  Lo-ad
	condition:
		any of ($a_*)
 
}