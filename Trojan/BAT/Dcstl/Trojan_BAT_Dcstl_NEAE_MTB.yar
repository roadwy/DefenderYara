
rule Trojan_BAT_Dcstl_NEAE_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 28 15 00 00 0a 0a 28 06 00 00 06 0b 07 07 6f 16 00 00 0a 07 6f 17 00 00 0a 6f 18 00 00 0a 25 06 16 06 8e 69 6f 19 00 00 0a 0c 6f 1a 00 00 0a 28 0f 00 00 0a 08 6f 1b 00 00 0a 2a } //02 00 
		$a_01_1 = {52 65 6c 65 61 73 65 5c 53 65 74 75 70 2e 70 64 62 } //02 00 
		$a_01_2 = {41 62 61 64 64 6f 6e 53 74 75 62 2e 53 74 61 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}