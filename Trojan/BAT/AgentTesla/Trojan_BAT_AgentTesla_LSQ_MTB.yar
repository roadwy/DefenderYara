
rule Trojan_BAT_AgentTesla_LSQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 0b 07 0a 2b 00 06 2a } //01 00  ଊਇ+⨆
		$a_03_1 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cc 90 00 } //01 00 
		$a_01_2 = {00 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 00 } //01 00  娀婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚Z
		$a_01_3 = {5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 5f 00 64 00 5f 00 ac 00 5f 00 5f 00 71 00 5f 00 4c 00 62 00 5f 00 b3 00 5f 00 97 00 70 00 5f 00 65 00 64 00 5f } //00 00 
	condition:
		any of ($a_*)
 
}