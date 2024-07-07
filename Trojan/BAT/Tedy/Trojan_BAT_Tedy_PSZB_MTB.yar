
rule Trojan_BAT_Tedy_PSZB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0e 72 5b 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 06 20 03 00 00 00 38 ba ff ff ff 11 0e 11 0e 28 90 01 01 00 00 06 11 0e 6f 04 00 00 0a 28 90 01 01 00 00 06 13 01 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}