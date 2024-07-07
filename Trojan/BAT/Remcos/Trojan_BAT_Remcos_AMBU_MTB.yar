
rule Trojan_BAT_Remcos_AMBU_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0a 07 11 0a 91 20 00 01 00 00 58 13 0b 07 11 09 91 13 0c 07 11 09 11 0c 08 11 08 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}