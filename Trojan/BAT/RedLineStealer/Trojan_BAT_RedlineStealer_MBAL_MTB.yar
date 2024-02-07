
rule Trojan_BAT_RedlineStealer_MBAL_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.MBAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 0a 00 00 0a 03 50 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 18 6f 90 01 01 00 00 0a 08 6f 10 00 00 0a 02 50 16 02 50 8e 69 90 00 } //01 00 
		$a_01_1 = {78 44 54 54 48 72 67 50 4c 5a 5a 7a 47 71 4b 42 46 66 6f 53 4b } //01 00  xDTTHrgPLZZzGqKBFfoSK
		$a_01_2 = {49 4d 76 78 50 72 6f 64 75 63 65 72 } //00 00  IMvxProducer
	condition:
		any of ($a_*)
 
}