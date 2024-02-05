
rule Trojan_BAT_Tedy_PSMP_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0c 2b 15 02 28 13 00 00 0a 0a 28 14 00 00 0a 06 6f 15 00 00 0a 0c 2b 00 08 2a } //00 00 
	condition:
		any of ($a_*)
 
}