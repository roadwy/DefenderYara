
rule Trojan_BAT_Taskun_ARAK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 6f 90 01 03 0a 61 07 11 05 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 00 11 05 15 58 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d b6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}