
rule Trojan_BAT_Tedy_SGB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.SGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 01 00 00 04 72 0f 00 00 70 28 19 00 00 0a 80 02 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}