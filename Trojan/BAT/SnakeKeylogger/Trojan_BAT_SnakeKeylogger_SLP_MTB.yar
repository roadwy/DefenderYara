
rule Trojan_BAT_SnakeKeylogger_SLP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 06 72 bd 04 00 70 6f ab 00 00 0a 75 29 00 00 01 0b 73 ac 00 00 0a 0c 20 00 0e 01 00 0d 07 08 09 28 38 00 00 06 00 d0 2b 00 00 01 28 a6 00 00 0a 72 c7 04 00 70 20 00 01 00 00 14 14 17 8d 12 00 00 01 25 16 08 6f ad 00 00 0a } //1
		$a_00_1 = {00 06 08 08 6c 28 b3 00 00 0a 6f b4 00 00 0a 00 00 08 18 58 0c 08 1f 0a fe 02 16 fe 01 0d 09 2d df } //1
		$a_81_2 = {42 64 61 79 42 75 64 64 79 2e 4c 6f 61 64 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 BdayBuddy.Loading.resources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}