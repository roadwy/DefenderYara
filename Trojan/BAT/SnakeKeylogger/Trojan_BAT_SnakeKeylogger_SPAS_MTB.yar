
rule Trojan_BAT_SnakeKeylogger_SPAS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {12 01 28 11 00 00 06 26 00 07 06 59 20 e8 03 00 00 6a 5a 7e 17 00 00 04 5b 6c 02 6c fe 04 0c 08 2d dd } //3
		$a_01_1 = {68 00 6b 00 79 00 78 00 44 00 70 00 45 00 68 00 70 00 51 00 78 00 4f 00 69 00 45 00 73 00 68 00 51 00 43 00 72 00 44 00 70 00 } //1 hkyxDpEhpQxOiEshQCrDp
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}