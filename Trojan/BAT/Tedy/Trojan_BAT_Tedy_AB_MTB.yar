
rule Trojan_BAT_Tedy_AB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e d7 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 2d 01 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}