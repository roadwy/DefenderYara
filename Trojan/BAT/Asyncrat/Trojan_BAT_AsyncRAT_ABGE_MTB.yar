
rule Trojan_BAT_AsyncRAT_ABGE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 09 12 02 28 08 00 00 06 00 73 12 00 00 0a 13 04 11 04 08 6f 13 00 00 0a 17 73 14 00 00 0a 13 05 00 11 05 02 16 02 8e 69 6f 15 00 00 0a 00 11 05 6f 16 00 00 0a 00 00 de 0d 11 05 2c 08 11 05 6f 0a 00 00 0a 00 dc 11 04 6f 17 00 00 0a 10 00 02 13 06 2b 00 11 06 2a } //01 00 
		$a_01_1 = {4b 00 61 00 74 00 79 00 75 00 73 00 68 00 61 00 } //01 00  Katyusha
		$a_01_2 = {53 00 6f 00 76 00 69 00 65 00 74 00 } //00 00  Soviet
	condition:
		any of ($a_*)
 
}