
rule Trojan_BAT_Tedy_PSSM_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 24 00 00 0a 2b 05 72 23 00 00 70 fe 0e 00 00 2b 05 72 23 00 00 70 72 35 00 00 70 2b 05 72 23 00 00 70 28 1e 00 00 0a 2b 05 72 23 00 00 70 72 57 00 00 70 2b 05 72 23 00 00 70 6f 1f 00 00 0a 2b 05 } //00 00 
	condition:
		any of ($a_*)
 
}