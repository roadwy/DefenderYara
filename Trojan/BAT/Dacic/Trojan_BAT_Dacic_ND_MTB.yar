
rule Trojan_BAT_Dacic_ND_MTB{
	meta:
		description = "Trojan:BAT/Dacic.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 06 93 0b 06 18 58 93 07 61 0b } //5
		$a_81_1 = {36 37 31 33 34 2e 39 30 31 33 34 2e 35 36 2e 30 39 } //3 67134.90134.56.09
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*3) >=8
 
}