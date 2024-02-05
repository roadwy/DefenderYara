
rule Trojan_BAT_Fauppod_ABLA_MTB{
	meta:
		description = "Trojan:BAT/Fauppod.ABLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 32 00 00 13 41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 37 00 00 13 41 00 6e 00 6e 00 61 00 4e 00 75 00 64 00 65 00 38 } //01 00 
		$a_01_1 = {53 00 49 00 4b 00 4a 00 44 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}