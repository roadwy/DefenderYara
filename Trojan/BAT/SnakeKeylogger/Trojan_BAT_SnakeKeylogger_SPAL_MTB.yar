
rule Trojan_BAT_SnakeKeylogger_SPAL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 6e 6b 42 6f 61 74 54 68 72 65 65 } //1 SunkBoatThree
		$a_01_1 = {53 75 6e 6b 42 6f 61 74 54 77 6f } //1 SunkBoatTwo
		$a_01_2 = {53 75 6e 6b 42 6f 61 74 4f 6e 65 } //1 SunkBoatOne
		$a_01_3 = {53 75 6e 6b 43 68 65 63 6b 65 72 } //1 SunkChecker
		$a_01_4 = {44 00 49 00 4b 00 4a 00 55 00 53 00 48 00 49 00 4a 00 55 00 57 00 44 00 4f 00 53 00 48 00 4e 00 49 00 4f 00 55 00 44 00 57 00 48 00 44 00 49 00 55 00 57 00 45 00 48 00 44 00 } //1 DIKJUSHIJUWDOSHNIOUDWHDIUWEHD
		$a_01_5 = {46 00 45 00 57 00 51 00 46 00 57 00 51 00 46 00 51 00 57 00 52 00 51 00 45 00 52 00 51 00 57 00 } //1 FEWQFWQFQWRQERQW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}