
rule Trojan_BAT_SnakeKeylogger_EB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {14 0b 14 0c 28 ?? ?? ?? 06 74 06 00 00 1b 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 08 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 0a 2b 00 06 2a } //10
		$a_81_1 = {42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 } //1 B________________________B
		$a_81_2 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 } //1 S____________________________S
		$a_81_3 = {44 69 61 6c 6f 67 73 4c 69 62 } //1 DialogsLib
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}