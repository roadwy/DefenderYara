
rule Trojan_BAT_Jalapeno_NE_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 95 11 05 13 05 61 } //5
		$a_01_1 = {00 00 95 11 0f 13 0f 61 } //5
		$a_01_2 = {95 11 0a 13 0a 61 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}