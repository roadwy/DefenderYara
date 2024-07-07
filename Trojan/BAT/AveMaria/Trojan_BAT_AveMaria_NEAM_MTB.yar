
rule Trojan_BAT_AveMaria_NEAM_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {5a 00 5a 00 52 00 5a 00 5a 00 5a 00 65 00 5a 00 5a 00 5a 00 66 00 5a 00 5a 00 5a 00 6c 00 5a 00 5a 00 5a 00 65 00 5a 00 5a 00 5a 00 63 00 5a 00 5a 00 5a 00 74 00 5a 00 5a 00 5a 00 69 00 5a 00 5a 00 5a 00 6f 00 5a 00 5a 00 5a 00 6e 00 5a 00 5a 00 5a 00 } //5 ZZRZZZeZZZfZZZlZZZeZZZcZZZtZZZiZZZoZZZnZZZ
		$a_01_1 = {63 00 76 00 62 00 63 00 68 00 72 00 65 00 35 00 79 00 } //5 cvbchre5y
		$a_01_2 = {70 00 6f 00 69 00 69 00 6c 00 75 00 6e 00 62 00 76 00 63 00 73 00 66 00 65 00 72 00 74 00 79 00 } //5 poiilunbvcsferty
		$a_01_3 = {6d 00 6a 00 68 00 6c 00 69 00 6f 00 75 00 37 00 35 00 64 00 67 00 76 00 66 00 } //5 mjhliou75dgvf
		$a_01_4 = {7b 00 30 00 7d 00 3a 00 2f 00 2f 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00 } //3 {0}://{1}.{2}.{3}
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3) >=23
 
}