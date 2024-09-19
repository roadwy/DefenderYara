
rule Trojan_BAT_Loki_E_MTB{
	meta:
		description = "Trojan:BAT/Loki.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 04 03 8e 69 5d 03 8e 69 58 03 8e 69 5d 91 } //2
		$a_01_1 = {03 17 58 04 5d 04 58 04 5d } //2
		$a_01_2 = {03 04 05 5d 05 58 05 5d 91 } //2
		$a_01_3 = {04 05 5d 05 58 05 5d 0a 03 06 91 0e 04 61 0e 05 59 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=10
 
}