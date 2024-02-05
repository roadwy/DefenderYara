
rule Trojan_AndroidOS_Sharkbot_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Sharkbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6e 10 1e 01 05 00 0c 05 6e 20 90 01 02 54 00 6e 20 90 01 02 04 00 6e 10 90 01 02 04 00 0c 04 71 30 78 16 43 01 0c 01 1a 03 90 01 02 6e 30 c8 02 12 03 62 03 90 01 02 6e 10 1d 01 03 00 0c 03 15 04 01 00 90 00 } //01 00 
		$a_03_1 = {1a 00 41 09 6e 10 90 01 02 07 00 0a 01 38 01 0d 00 52 70 90 01 02 59 70 90 01 02 6e 10 90 01 02 07 00 6e 10 90 01 02 07 00 0e 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}