
rule Trojan_BAT_Heracles_NK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 09 6e 08 8e 69 6a 5d d4 91 13 0d 11 04 11 0d 58 11 06 09 95 58 } //5
		$a_01_1 = {5f d2 9c 00 11 0f 17 6a 58 13 0f 11 0f 11 07 8e 69 17 59 6a fe 02 16 fe 01 } //4
		$a_01_2 = {5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 07 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=12
 
}