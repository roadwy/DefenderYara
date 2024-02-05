
rule Trojan_BAT_Tedy_PSQX_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 0d 01 00 0a 6f 0e 01 00 0a 28 0f 01 00 0a 72 39 5d 00 70 28 10 01 00 0a 28 b3 00 00 0a 26 02 28 b4 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}