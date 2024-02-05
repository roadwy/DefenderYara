
rule Trojan_BAT_Taskun_ARBJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 11 09 11 04 5d 13 0a 11 09 11 05 5d 13 0b 08 11 0a 91 13 0c 09 11 0b 6f 90 01 03 0a 13 0d 08 11 09 17 58 11 04 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 08 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}