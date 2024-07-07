
rule Trojan_BAT_Tedy_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 02 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 02 00 0a 08 6f 90 01 01 02 00 0a 06 6f 90 01 01 01 00 0a 0d 09 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}