
rule Trojan_AndroidOS_Asacub_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Asacub.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 75 2e 61 73 73 75 6d 70 74 69 6f 6e 2e 68 61 76 65 } //1 ru.assumption.have
		$a_01_1 = {67 65 74 48 69 6e 74 48 69 64 65 49 63 6f 6e } //1 getHintHideIcon
		$a_01_2 = {50 72 65 6d 61 74 75 72 65 54 75 6e 65 } //1 PrematureTune
		$a_01_3 = {59 61 72 64 52 65 73 74 61 75 72 61 6e 74 } //1 YardRestaurant
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}