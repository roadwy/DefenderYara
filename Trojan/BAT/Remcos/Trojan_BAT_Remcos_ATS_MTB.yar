
rule Trojan_BAT_Remcos_ATS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ATS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 06 2b 1a 00 09 11 06 08 11 06 91 07 11 06 07 8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}