
rule Trojan_BAT_Nanocore_ABKQ_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 06 16 73 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 07 08 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 0d 09 13 04 de 1e 08 2c 06 08 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {55 72 6c 54 6f 6b 65 6e 44 65 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}