
rule Trojan_BAT_Bladabindi_GPB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 02 8e 69 17 da 0c 02 08 91 90 01 02 61 0d 02 8e 69 17 d6 90 00 } //5
		$a_03_1 = {91 09 61 07 11 90 01 01 91 61 b4 9c 11 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}