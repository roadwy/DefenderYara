
rule Trojan_BAT_AgentTesla_LSM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 00 } //01 00  娀婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚婚Z
		$a_01_1 = {00 54 30 30 30 31 00 } //01 00 
		$a_01_2 = {00 54 30 30 30 32 00 } //01 00 
		$a_01_3 = {00 54 30 30 30 33 00 } //01 00 
		$a_01_4 = {00 54 30 30 30 34 00 } //01 00 
		$a_01_5 = {00 54 30 30 30 35 00 } //01 00 
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_7 = {42 75 6e 69 66 75 } //01 00  Bunifu
		$a_81_8 = {65 78 74 42 6f 78 } //00 00  extBox
	condition:
		any of ($a_*)
 
}