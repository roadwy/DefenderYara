
rule Trojan_BAT_Heracles_AKP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 24 01 00 06 17 8d 90 01 03 01 25 16 08 75 a9 00 00 01 1f 10 6f 90 01 03 0a a2 14 14 16 17 90 00 } //1
		$a_03_1 = {11 0c 74 ac 00 00 01 02 16 02 8e 69 6f 90 01 03 0a 11 0c 75 ac 00 00 01 6f 90 01 03 0a 1b 13 14 2b bf de 49 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}