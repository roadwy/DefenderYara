
rule Trojan_BAT_Spynoon_AAIQ_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AAIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {01 0d 08 09 16 1a 6f 90 01 01 00 00 0a 26 09 16 28 90 01 01 00 00 0a 13 04 08 16 73 90 01 01 00 00 0a 13 05 11 04 8d 90 01 01 00 00 01 13 06 11 05 11 06 16 11 04 6f 90 01 01 00 00 0a 26 11 06 13 07 dd 90 01 01 00 00 00 11 05 39 90 01 01 00 00 00 11 05 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00  ReadAsByteArrayAsync
	condition:
		any of ($a_*)
 
}