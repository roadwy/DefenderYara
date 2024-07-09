
rule Trojan_BAT_SnakeKeylogger_EN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 "
		
	strings :
		$a_03_0 = {1b 0a 06 17 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 06 16 28 ?? ?? ?? 06 a2 02 7b ?? ?? ?? 04 06 28 ?? ?? ?? 0a 26 06 } //20
		$a_81_1 = {46 54 5f 46 54 31 } //1 FT_FT1
		$a_81_2 = {46 54 5f 46 54 32 } //1 FT_FT2
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=24
 
}