
rule Trojan_BAT_Lokibot_MBEN_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 8e 69 5d 13 04 07 09 6f 90 01 01 00 00 0a 5d 13 08 06 11 04 91 13 09 09 11 08 6f 90 01 01 00 00 0a 13 0a 02 06 07 28 90 01 01 00 00 06 13 0b 02 11 09 11 0a 11 0b 28 90 01 01 00 00 06 13 0c 06 11 04 11 0c 20 00 01 00 00 5d d2 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d a9 90 00 } //01 00 
		$a_01_1 = {4a 65 6f 70 61 72 64 79 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //00 00  JeopardyGame.Properties.Resource
	condition:
		any of ($a_*)
 
}