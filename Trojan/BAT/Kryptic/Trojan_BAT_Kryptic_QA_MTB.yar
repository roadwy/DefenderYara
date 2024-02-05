
rule Trojan_BAT_Kryptic_QA_MTB{
	meta:
		description = "Trojan:BAT/Kryptic.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 16 17 73 90 01 03 0a 0b 73 90 01 03 0a 0c 07 6f 90 01 03 0a 0d 2b 12 00 08 09 d2 6f 90 01 03 0a 00 07 6f 90 01 03 0a 0d 00 09 15 fe 01 16 fe 01 13 04 11 04 2d e1 90 00 } //01 00 
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  01 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  01 00 
		$a_80_3 = {54 6f 41 72 72 61 79 } //ToArray  00 00 
	condition:
		any of ($a_*)
 
}