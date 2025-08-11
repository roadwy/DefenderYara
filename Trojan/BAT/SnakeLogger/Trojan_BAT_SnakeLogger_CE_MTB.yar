
rule Trojan_BAT_SnakeLogger_CE_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2c 02 16 0b 28 ?? 00 00 0a 17 fe 02 0c 19 8d ?? 00 00 1b 25 16 06 } //2
		$a_01_1 = {1b 5d 0b 07 1a 2e 0e 07 19 2e 0a 07 18 2e 06 07 17 fe 01 2b 01 17 } //2
		$a_01_2 = {72 00 34 00 4e 00 64 00 30 00 6d 00 5f 00 35 00 41 00 31 00 74 00 } //1 r4Nd0m_5A1t
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}