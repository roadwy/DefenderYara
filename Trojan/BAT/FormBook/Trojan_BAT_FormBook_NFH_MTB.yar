
rule Trojan_BAT_FormBook_NFH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {04 6f bf 00 00 0a 0a 06 74 36 00 00 01 0b 2b 00 07 2a } //01 00 
		$a_01_1 = {41 75 74 79 20 32 } //01 00  Auty 2
		$a_01_2 = {72 74 62 42 53 44 52 } //01 00  rtbBSDR
		$a_01_3 = {41 6c 67 6f 72 69 74 68 6d 53 69 6d 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  AlgorithmSimulator.Properties.Resources
	condition:
		any of ($a_*)
 
}