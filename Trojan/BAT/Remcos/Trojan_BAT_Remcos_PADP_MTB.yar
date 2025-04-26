
rule Trojan_BAT_Remcos_PADP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PADP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 07 08 11 07 91 20 7e 06 00 00 59 d2 9c 00 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d dc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}