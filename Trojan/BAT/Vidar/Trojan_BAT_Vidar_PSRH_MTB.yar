
rule Trojan_BAT_Vidar_PSRH_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {60 0c 28 1e 00 00 0a 7e 01 00 00 04 02 08 6f 1f 00 00 0a 28 20 00 00 0a a5 01 00 00 1b 0b 11 07 20 89 6e 9b 64 5a 20 d0 c5 ea 58 61 } //00 00 
	condition:
		any of ($a_*)
 
}