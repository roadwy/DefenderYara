
rule Backdoor_BAT_Sootbot_B{
	meta:
		description = "Backdoor:BAT/Sootbot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 1d 12 00 1a 28 90 01 01 00 00 06 90 00 } //1
		$a_03_1 = {06 08 06 25 13 05 08 25 13 06 11 05 11 06 6f 90 01 04 07 d2 59 d2 25 13 07 6f 90 00 } //1
		$a_03_2 = {0b 06 07 16 07 8e 69 16 6f 90 01 04 26 14 0b 7e 90 01 04 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}