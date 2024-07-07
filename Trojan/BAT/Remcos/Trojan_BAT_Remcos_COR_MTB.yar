
rule Trojan_BAT_Remcos_COR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.COR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 2b 8b 00 00 8d 11 00 00 01 25 d0 04 00 00 04 28 90 01 03 0a 0a 20 73 66 01 00 8d 11 00 00 01 25 d0 05 00 00 04 28 90 01 03 0a 0b 07 28 90 01 03 06 0c 06 28 90 01 03 06 0d 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}