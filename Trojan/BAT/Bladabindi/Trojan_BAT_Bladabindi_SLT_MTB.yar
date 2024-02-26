
rule Trojan_BAT_Bladabindi_SLT_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 0a 16 2b 01 16 45 04 00 00 00 02 00 00 00 07 00 00 00 0e 00 00 00 13 00 00 00 2b 26 03 0b 17 2b e4 06 8e 69 0c 18 2b dd 16 0d 19 2b d8 2b 17 07 09 07 09 91 06 09 08 5d 91 28 90 01 03 06 9c 1a 2b c3 09 17 58 0d 09 07 8e 69 32 e3 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}