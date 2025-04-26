
rule Trojan_BAT_Mardom_SQ_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {5a 6b 6c 79 6d 72 72 71 6c 6a 63 } //2 Zklymrrqljc
		$a_81_1 = {24 36 39 37 63 65 66 66 34 2d 31 33 30 66 2d 34 36 38 61 2d 62 62 65 65 2d 34 62 37 61 30 38 30 31 61 36 66 30 } //2 $697ceff4-130f-468a-bbee-4b7a0801a6f0
		$a_81_2 = {74 6f 79 73 63 65 6e 74 65 72 2e 63 6c } //2 toyscenter.cl
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}