
rule Trojan_BAT_Strictor_AMCZ_MTB{
	meta:
		description = "Trojan:BAT/Strictor.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 ?? 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 2a } //4
		$a_01_1 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 00 53 74 72 69 6e 67 00 43 6f 6e 63 61 74 00 50 72 6f 63 65 73 73 00 53 74 61 72 74 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}