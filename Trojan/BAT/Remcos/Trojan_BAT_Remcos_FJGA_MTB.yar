
rule Trojan_BAT_Remcos_FJGA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FJGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f 90 01 03 0a 13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 13 04 11 04 08 6f 90 01 03 0a fe 04 13 08 11 08 2d c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}