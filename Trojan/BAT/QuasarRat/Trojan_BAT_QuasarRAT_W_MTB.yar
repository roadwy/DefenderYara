
rule Trojan_BAT_QuasarRAT_W_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8e 69 6a 5d 69 06 } //2
		$a_01_1 = {8e 69 6a 5d 69 91 02 08 02 8e 69 6a 5d 69 91 61 06 } //2
		$a_01_2 = {08 17 6a 58 06 } //2
		$a_01_3 = {8e 69 6a 5d 69 91 59 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}