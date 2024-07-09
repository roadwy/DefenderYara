
rule Trojan_BAT_SnakeKeylogger_ABYC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 90 0a 19 00 7e ?? 00 00 04 6f } //3
		$a_01_1 = {57 00 6f 00 72 00 64 00 4c 00 69 00 73 00 74 00 41 00 6e 00 61 00 6c 00 79 00 73 00 65 00 72 00 32 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WordListAnalyser2.Properties.Resources
		$a_01_2 = {53 00 70 00 61 00 63 00 65 00 54 00 65 00 61 00 6d 00 } //1 SpaceTeam
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}