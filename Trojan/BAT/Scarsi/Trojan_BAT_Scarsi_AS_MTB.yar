
rule Trojan_BAT_Scarsi_AS_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 0a 2b 17 11 04 09 06 09 8e 69 5d 91 08 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 08 8e 69 32 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Scarsi_AS_MTB_2{
	meta:
		description = "Trojan:BAT/Scarsi.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 0b 2b f8 02 50 06 91 16 2c 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}