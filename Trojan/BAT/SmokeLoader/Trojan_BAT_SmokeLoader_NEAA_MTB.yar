
rule Trojan_BAT_SmokeLoader_NEAA_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 12 03 28 1e 00 00 0a 06 07 02 07 18 6f 1f 00 00 0a 1f 10 28 20 00 00 0a 6f 21 00 00 0a de 0a } //10
		$a_01_1 = {66 00 69 00 6c 00 69 00 66 00 69 00 6c 00 6d 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //5 filifilm.com.br
		$a_01_2 = {53 6f 63 63 65 72 } //2 Soccer
		$a_01_3 = {42 61 73 6b 65 74 62 61 6c 6c } //2 Basketball
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=19
 
}