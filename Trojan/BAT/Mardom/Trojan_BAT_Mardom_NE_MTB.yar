
rule Trojan_BAT_Mardom_NE_MTB{
	meta:
		description = "Trojan:BAT/Mardom.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 18 5d 26 06 19 5d 2c 04 06 1b 5d 26 06 17 58 0a 06 } //05 00 
		$a_01_1 = {07 18 5d 2d 06 11 06 07 58 13 06 07 17 58 0b 07 09 31 ed } //01 00 
		$a_81_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  System.Security.Cryptography
		$a_81_3 = {52 69 6a 6e 64 61 65 6c } //00 00  Rijndael
	condition:
		any of ($a_*)
 
}