
rule Trojan_BAT_FormBook_NFH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {04 6f bf 00 00 0a 0a 06 74 36 00 00 01 0b 2b 00 07 2a } //5
		$a_01_1 = {41 75 74 79 20 32 } //1 Auty 2
		$a_01_2 = {72 74 62 42 53 44 52 } //1 rtbBSDR
		$a_01_3 = {41 6c 67 6f 72 69 74 68 6d 53 69 6d 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 AlgorithmSimulator.Properties.Resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}