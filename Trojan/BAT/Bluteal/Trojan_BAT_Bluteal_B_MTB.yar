
rule Trojan_BAT_Bluteal_B_MTB{
	meta:
		description = "Trojan:BAT/Bluteal.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 } //01 00 
		$a_03_1 = {13 05 11 05 2d d5 07 73 90 01 04 0d 00 72 d8 02 00 70 13 06 1e 8d 45 00 00 01 13 07 73 90 01 04 13 08 16 13 0c 2b 21 00 11 07 11 0c 11 06 08 11 06 6f 90 01 04 6f 90 01 04 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}