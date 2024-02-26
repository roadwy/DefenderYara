
rule Trojan_BAT_Taskun_ARA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 07 06 08 58 17 58 17 59 07 09 58 17 58 17 59 6f 90 01 03 0a 13 10 12 10 28 90 01 03 0a 13 0a 11 05 11 04 11 0a 9c 11 04 17 58 13 04 09 17 58 0d 09 17 fe 04 13 0b 11 0b 2d c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}