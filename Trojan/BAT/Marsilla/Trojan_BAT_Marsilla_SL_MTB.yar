
rule Trojan_BAT_Marsilla_SL_MTB{
	meta:
		description = "Trojan:BAT/Marsilla.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 09 11 06 09 91 06 11 0b 95 61 d2 9c 09 17 58 0d 09 11 06 8e 69 32 84 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}