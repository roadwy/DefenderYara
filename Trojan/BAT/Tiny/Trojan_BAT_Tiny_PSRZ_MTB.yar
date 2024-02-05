
rule Trojan_BAT_Tiny_PSRZ_MTB{
	meta:
		description = "Trojan:BAT/Tiny.PSRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 06 28 15 00 00 0a 26 2b 54 73 16 00 00 0a 13 0a 00 00 11 0a 07 11 04 6f 17 00 00 0a 00 00 de 1b } //00 00 
	condition:
		any of ($a_*)
 
}