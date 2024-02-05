
rule Trojan_BAT_Tedy_PSWR_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 11 05 6f 14 00 00 0a 72 0f 00 00 70 72 25 00 00 70 6f 90 01 01 00 00 0a 00 11 05 02 07 6f 90 01 01 00 00 0a 00 00 de 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}