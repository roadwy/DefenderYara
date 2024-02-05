
rule Trojan_BAT_Taskun_ARAS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 08 11 04 08 8e 69 5d 08 11 04 08 8e 69 5d 91 09 11 04 09 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 08 11 04 17 58 08 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 11 04 15 58 13 04 00 11 04 16 fe 04 16 fe 01 13 08 11 08 2d a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}