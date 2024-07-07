
rule Trojan_BAT_Remcos_MAQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 40 01 00 0a 13 06 02 73 41 01 00 0a 13 07 11 07 74 90 01 03 01 11 06 75 90 01 03 01 16 73 42 01 00 0a 13 08 1a 13 14 2b a8 02 8e 69 17 da 17 d6 8d 90 01 03 01 13 09 11 08 75 b9 00 00 01 11 09 75 09 00 00 1b 16 11 09 75 09 00 00 1b 8e 69 6f 43 90 01 03 13 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}