
rule Trojan_BAT_BitRAT_AB_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 bc 05 00 70 28 60 00 00 0a 74 31 00 00 01 0a 2b 00 06 2a } //01 00 
		$a_01_1 = {07 8e 69 17 59 0d 16 13 04 2b 15 07 11 04 07 11 04 91 20 94 03 00 00 59 d2 9c 11 04 17 58 13 04 11 04 09 31 e6 } //01 00 
		$a_01_2 = {45 00 6e 00 67 00 6f 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}