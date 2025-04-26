
rule Trojan_BAT_Remcos_KAAQ_{
	meta:
		description = "Trojan:BAT/Remcos.KAAQ!!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 11 09 11 07 95 58 20 ff 00 00 00 5f 95 61 d2 9c 00 11 10 17 6a 58 13 10 } //1
		$a_01_1 = {35 00 35 00 43 00 41 00 35 00 44 00 41 00 43 00 42 00 30 00 45 00 45 00 39 00 34 00 39 00 46 00 34 00 33 00 } //1 55CA5DACB0EE949F43
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}