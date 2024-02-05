
rule Backdoor_BAT_Prostbot_A{
	meta:
		description = "Backdoor:BAT/Prostbot.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0b 16 0c 38 36 00 00 00 02 08 6f 90 01 01 00 00 90 01 01 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c 90 00 } //01 00 
		$a_00_1 = {53 74 61 73 69 20 42 6f 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}