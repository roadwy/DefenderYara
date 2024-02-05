
rule Trojan_BAT_Remcos_AAEL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AAEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 00 7e 90 01 01 00 00 04 06 7e 90 01 01 00 00 04 06 91 20 81 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 90 01 01 00 00 04 8e 69 fe 04 0b 07 2d d7 90 00 } //01 00 
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}