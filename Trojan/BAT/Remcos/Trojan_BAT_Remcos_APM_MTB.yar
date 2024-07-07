
rule Trojan_BAT_Remcos_APM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.APM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 16 0b 03 17 33 20 02 7b 27 00 00 04 6f 73 00 00 0a 0b 07 15 33 05 28 56 00 00 06 02 7b 28 00 00 04 16 07 d2 9c 2a 02 7b 27 00 00 04 02 7b 28 00 00 04 06 03 06 59 6f 74 00 00 0a 0b 07 2d 05 28 56 00 00 06 06 07 58 0a 06 03 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}