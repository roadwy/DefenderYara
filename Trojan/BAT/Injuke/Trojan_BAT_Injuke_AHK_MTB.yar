
rule Trojan_BAT_Injuke_AHK_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 06 17 58 0a 15 2c 0a 06 08 8e 69 32 e3 } //00 00 
	condition:
		any of ($a_*)
 
}