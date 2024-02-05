
rule Trojan_BAT_Disco_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Disco.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 09 6f 90 01 01 00 00 0a 13 04 06 11 04 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 02 0c 06 6f 90 01 01 00 00 0a 08 16 08 8e 69 6f 90 01 01 00 00 0a 13 05 de 0e 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}