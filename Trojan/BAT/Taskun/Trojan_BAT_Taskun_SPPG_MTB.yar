
rule Trojan_BAT_Taskun_SPPG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {61 11 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0b 07 11 09 11 08 6a 5d d4 11 0b 28 90 01 03 0a 9c 11 09 17 6a 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}