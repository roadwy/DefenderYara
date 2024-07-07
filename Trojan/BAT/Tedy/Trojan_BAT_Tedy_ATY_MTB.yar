
rule Trojan_BAT_Tedy_ATY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 01 00 00 04 a2 25 17 7e 90 01 01 00 00 04 a2 0b 06 14 28 90 01 01 00 00 0a 2c 12 06 14 17 8d 90 01 03 01 25 16 07 a2 90 00 } //2
		$a_01_1 = {42 00 6f 00 6e 00 6f 00 73 00 75 00 61 00 } //1 Bonosua
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Tedy_ATY_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0d 02 06 02 06 91 03 61 d2 9c 06 17 58 0a 06 02 28 90 01 01 00 00 06 25 26 69 32 e7 90 00 } //1
		$a_01_1 = {16 0c 2b 1c 07 08 18 5b 02 08 18 28 63 00 00 06 25 26 1f 10 28 ac 00 00 06 25 26 9c 08 18 58 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Tedy_ATY_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f 90 01 03 0a 06 72 1f 00 00 70 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 16 6f 90 01 03 0a 06 17 6f 90 01 03 0a 73 16 00 00 0a 25 06 90 00 } //2
		$a_01_1 = {64 65 66 65 6e 64 65 72 20 69 73 6b 6c } //1 defender iskl
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}