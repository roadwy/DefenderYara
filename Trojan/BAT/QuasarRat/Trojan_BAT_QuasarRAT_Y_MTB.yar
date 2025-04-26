
rule Trojan_BAT_QuasarRAT_Y_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {03 08 03 8e 69 5d 1d 59 1d 58 03 08 03 8e 69 5d } //2
		$a_01_1 = {59 17 59 91 07 08 07 8e 69 5d } //2
		$a_01_2 = {59 17 59 91 61 03 08 } //2
		$a_01_3 = {5d 19 59 19 58 d2 9c 08 17 58 0c } //2
		$a_01_4 = {08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}