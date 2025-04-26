
rule Trojan_BAT_Remcos_JGM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.JGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 02 08 91 11 04 61 d2 9c 00 08 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}