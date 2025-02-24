
rule Trojan_BAT_Tedy_EANT_MTB{
	meta:
		description = "Trojan:BAT/Tedy.EANT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 18 07 28 1b 00 00 0a 0c 06 12 02 28 1c 00 00 0a 6f 1d 00 00 0a 07 17 58 0b 07 28 1e 00 00 0a 32 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}