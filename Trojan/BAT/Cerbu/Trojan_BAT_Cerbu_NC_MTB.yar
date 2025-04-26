
rule Trojan_BAT_Cerbu_NC_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {36 39 46 32 34 32 30 38 2d 42 41 42 41 2d 34 30 37 34 2d 42 35 34 35 2d 37 34 42 32 46 34 35 44 44 37 39 44 } //3 69F24208-BABA-4074-B545-74B2F45DD79D
		$a_01_1 = {0d 07 8e 69 13 04 08 8e 69 13 05 16 } //1
		$a_01_2 = {11 08 11 0c 07 11 06 11 0c 58 91 9c 11 0c 17 58 } //1
	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}