
rule Trojan_BAT_Lokibot_AL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 20 00 07 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 00 09 18 58 0d 00 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d d1 90 00 } //01 00 
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 66 00 65 00 72 00 6f 00 6d 00 65 00 74 00 72 00 79 00 } //00 00  Interferometry
	condition:
		any of ($a_*)
 
}