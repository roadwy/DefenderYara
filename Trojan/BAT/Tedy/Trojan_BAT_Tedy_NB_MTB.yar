
rule Trojan_BAT_Tedy_NB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 6a da b7 17 d6 17 da 17 d6 17 da 17 d6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}