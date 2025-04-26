
rule Trojan_BAT_Jalapeno_MBXW_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MBXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 79 01 00 00 91 1f 45 58 13 17 } //3
		$a_01_1 = {46 69 6e 61 6c 50 72 6f 6a 65 63 74 46 6f 72 4e 45 54 44 } //2 FinalProjectForNETD
		$a_01_2 = {30 36 33 63 31 30 34 35 38 64 64 37 } //1 063c10458dd7
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}