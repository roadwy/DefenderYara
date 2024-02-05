
rule Trojan_BAT_Injuke_AIN_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {38 1d 00 00 00 09 6f 90 01 03 0a 13 07 08 11 07 07 02 11 07 18 5a 18 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}