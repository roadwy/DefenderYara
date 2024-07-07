
rule Trojan_BAT_Heracles_LJAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.LJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 07 11 06 9a 1f 10 28 90 01 01 00 00 06 9c 00 11 06 17 58 13 06 90 00 } //3
		$a_01_1 = {41 46 45 4b 4a 44 46 4e 53 4a 4b 46 41 4a 4b 46 53 44 4e 4a 4b 46 4a 4b 4c } //1 AFEKJDFNSJKFAJKFSDNJKFJKL
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}