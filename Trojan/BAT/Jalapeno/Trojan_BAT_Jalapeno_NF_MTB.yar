
rule Trojan_BAT_Jalapeno_NF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 0b 11 26 58 1d 11 22 58 61 d2 13 1a } //2
		$a_01_1 = {11 19 18 91 11 19 19 91 1f 10 62 60 11 19 16 91 1e 62 60 11 19 17 91 1f 18 62 60 02 65 61 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Jalapeno_NF_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {02 6f 0f 00 00 0a 0a 20 5e 1d 44 4c 03 58 20 24 00 00 00 d3 } //3
		$a_01_1 = {5f 07 25 17 58 0b 61 d2 0d 25 1e 63 07 25 17 58 0b 61 d2 } //2
		$a_81_2 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_3 = {34 39 43 43 36 42 33 38 2d 33 35 35 43 2d 34 46 36 38 2d 42 46 44 43 2d 31 32 30 35 37 34 32 46 35 41 39 33 } //1 49CC6B38-355C-4F68-BFDC-1205742F5A93
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=7
 
}