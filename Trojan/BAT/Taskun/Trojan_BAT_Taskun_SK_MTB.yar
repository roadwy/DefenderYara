
rule Trojan_BAT_Taskun_SK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 18 6f 90 01 03 0a 13 07 08 07 18 5b 11 07 1f 10 28 90 01 03 0a 9c 07 18 58 0b 07 06 6f 90 01 03 0a fe 04 13 08 11 08 2d d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}