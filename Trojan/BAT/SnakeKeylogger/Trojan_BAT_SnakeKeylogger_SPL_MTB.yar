
rule Trojan_BAT_SnakeKeylogger_SPL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 7a 6c 65 6e 6b 6f 6b 61 } //01 00  Ezlenkoka
		$a_01_1 = {46 61 63 65 62 6f 6f 6b 55 73 65 72 50 6f 73 74 4b 65 79 50 68 72 61 73 } //01 00  FacebookUserPostKeyPhras
		$a_01_2 = {46 61 63 65 62 6f 6f 6b 50 65 72 73 6f 6e 61 6c 69 74 79 49 6e 73 69 67 68 74 73 50 65 72 73 6f 6e 61 6c 69 74 79 } //01 00  FacebookPersonalityInsightsPersonality
		$a_01_3 = {4d 6f 6f 64 44 65 74 65 63 74 6f 72 2e 44 61 74 61 41 63 63 65 73 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  MoodDetector.DataAccess.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}