
rule Trojan_BAT_Remcos_PSJU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PSJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 17 11 11 11 16 11 17 6f 24 00 00 0a 00 00 11 14 17 58 13 14 11 14 11 13 8e 69 32 c7 00 72 97 03 00 70 13 18 1f 10 28 1f 00 00 0a 13 19 72 b7 03 00 70 13 1a 72 1d 04 00 70 13 1b 72 73 04 00 70 73 25 00 00 0a 28 26 00 00 0a 28 27 00 00 0a 74 07 00 00 02 13 1c 7e 01 00 00 04 2c 02 2b 25 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}