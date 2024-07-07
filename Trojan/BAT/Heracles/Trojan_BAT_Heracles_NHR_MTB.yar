
rule Trojan_BAT_Heracles_NHR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 c2 00 00 0a 02 6f 90 01 03 0a 0b 06 07 6f 90 01 03 0a 28 90 01 03 0a 20 90 01 03 61 72 90 01 03 70 20 90 01 03 61 28 90 01 03 2b 72 90 01 03 70 6f 90 01 03 0a 0c de 0a 90 00 } //5
		$a_01_1 = {4f 00 78 00 79 00 44 00 6f 00 72 00 6b 00 73 00 5f 00 76 00 33 00 } //1 OxyDorks_v3
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_NHR_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 1b 00 00 0a 0a 72 90 01 03 70 0b 72 90 01 03 70 0c 06 72 90 01 03 70 08 6f 90 01 03 0a 00 06 72 90 01 03 70 07 6f 90 01 03 0a 00 73 90 01 03 0a 0d 09 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 00 09 6f 90 01 03 0a 17 6f 90 01 03 0a 00 09 6f 90 01 03 0a 17 6f 90 01 03 0a 00 09 6f 90 01 03 0a 17 6f 90 01 03 0a 00 07 08 28 90 01 03 0a 90 00 } //5
		$a_01_1 = {59 6f 75 72 5f 53 6b 69 64 64 65 64 5f 53 70 6f 6f 66 65 72 } //1 Your_Skidded_Spoofer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}