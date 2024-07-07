
rule Trojan_BAT_Nanocore_ABXE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 8d 90 01 01 00 00 01 0d 16 13 07 2b 15 09 11 07 08 11 07 9a 1f 10 28 90 01 02 00 0a 9c 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d de 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}