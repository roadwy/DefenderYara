
rule Backdoor_BAT_NanoBot_SK_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}