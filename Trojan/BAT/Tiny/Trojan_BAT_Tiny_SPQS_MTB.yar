
rule Trojan_BAT_Tiny_SPQS_MTB{
	meta:
		description = "Trojan:BAT/Tiny.SPQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 06 17 7e 06 00 00 0a a2 11 06 18 06 72 e7 00 00 70 6f 90 01 03 0a a2 11 06 19 17 8c 0b 00 00 01 a2 11 06 0d 06 90 00 } //01 00 
		$a_01_1 = {4b 00 55 00 52 00 45 00 4b 00 3a 00 2f 00 2f 00 63 00 6f 00 64 00 69 00 75 00 6d 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 63 00 6f 00 6d 00 2f 00 52 00 75 00 6e 00 50 00 65 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}