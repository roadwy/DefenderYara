
rule Trojan_BAT_Remcos_ADIV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ADIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 16 00 00 04 06 7e 16 00 00 04 06 91 20 44 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 16 00 00 04 8e 69 fe 04 0b 07 2d d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}