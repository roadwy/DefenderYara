
rule Trojan_BAT_Netwire_EXTF_MTB{
	meta:
		description = "Trojan:BAT/Netwire.EXTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 07 09 6f d1 00 00 0a 00 07 18 6f d2 00 00 0a 00 07 6f d3 00 00 0a 03 16 03 8e 69 } //01 00 
		$a_01_1 = {5a 00 45 00 72 00 6f 00 4b 00 61 00 52 00 75 00 6e 00 } //01 00 
		$a_01_2 = {49 00 69 00 61 00 6d 00 73 00 4c 00 61 00 61 00 4f 00 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}