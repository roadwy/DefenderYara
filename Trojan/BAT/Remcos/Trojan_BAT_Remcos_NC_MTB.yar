
rule Trojan_BAT_Remcos_NC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {61 63 36 64 32 64 37 66 2d 64 33 38 66 2d 34 62 66 63 2d 61 36 38 37 2d 39 31 36 30 30 38 30 30 32 65 37 31 } //3 ac6d2d7f-d38f-4bfc-a687-916008002e71
		$a_01_1 = {0d 09 18 5b 13 04 11 04 18 5a 13 05 11 05 09 fe 01 13 09 11 09 } //1
		$a_01_2 = {09 16 31 07 11 07 16 fe 03 2b 01 16 13 0a 11 0a 2c 0a 03 11 07 } //1
	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}